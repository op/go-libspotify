// Copyright 2013 Örjan Persson
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package spotify adds language bindings for spotify in Go. The libspotify
// C API package allows third-party developers to write applications which
// utilize the Spotify music streaming service.
package spotify

/*
#cgo pkg-config: libspotify
#include <libspotify/api.h>
#include "libspotify.h"
*/
import "C"

import (
	"errors"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	ErrMissingApplicationKey = errors.New("spotify: application key is required")
)

// Config represents the configuration setup when creating a new session.
type Config struct {
	// ApplicationKey is required and can be acquired from developer.spotify.com.
	ApplicationKey []byte

	// ApplicationName is used to determine cache locations and user agent.
	ApplicationName string

	// UserAgent is used when communicating with Spotify. If left empty, it
	// will automatically be created based on ApplicationName.
	UserAgent string

	// CacheLocation defines were Spotify will write any cache
	// files. This includes tracks, browse results and coverarts.
	// Leave empty to disable.
	CacheLocation string

	// SettingsLocation defines where Spotify will write settings
	// and per-user cache items. This includes playlists etc. It
	// may be the same location as the CacheLocation.
	//
	// Note: this directory will not be automatically created.
	SettingsLocation string

	// CompressPlaylists, if enabled, will compress local copies
	// of playlists to reduce disk space usage.
	CompressPlaylists bool

	// DisablePlaylistMetadataCache disables metadata caches for
	// playlists. It reduces disk space usage at the expense of
	// needing to request metadata from Spotify backend when
	// loading lists.
	DisablePlaylistMetadataCache bool

	// InitiallyUnloadPlaylists will avoid loading playlists into
	// RAM on startup if enabled.
	InitiallyUnloadPlaylists bool

	// TODO device_id
	// TODO proxy
	// TODO ca_certs
	// TODO tracefile

	AudioConsumer AudioConsumer
}

// Connection state describes the state of the connection of a session.
type ConnectionState C.sp_connectionstate

const (
	// User not yet logged in
	ConnectionStateLoggedOut ConnectionState = C.SP_CONNECTION_STATE_LOGGED_OUT

	// Logged in against an Spotify accesspoint
	ConnectionStateLoggedIn = C.SP_CONNECTION_STATE_LOGGED_IN

	// Was logged in, but has now been disconnected
	ConnectionStateDisconnected = C.SP_CONNECTION_STATE_DISCONNECTED

	// Connection state is undefined
	ConnectionStateUndefined = C.SP_CONNECTION_STATE_UNDEFINED

	// Logged in, but in offline mode
	ConnectionStateOffline = C.SP_CONNECTION_STATE_OFFLINE
)

var (
	// once is used to initiate the global state of the package.
	once sync.Once

	// callbacks is a static set of callbacks used for all sessions.
	callbacks C.sp_session_callbacks
)

// event is an internal type passed around to wake the main session thread up.
type event int

// Credentials are used when logging a user in.
type Credentials struct {
	// Username is the spotify username.
	Username string

	// Password for the spotify username.
	Password string

	// Blob is an opaque data chunk used when logging in instead of password. If
	// login is successful and the remember flag set to true, this should be the
	// data blob retrieved from CredentialsBlobUpdates.
	Blob []byte
}

// Session is the representation of a Spotify session.
type Session struct {
	config     C.sp_session_config
	sp_session *C.sp_session
	mu         sync.Mutex

	loggedIn  chan error
	loggedOut chan struct{}

	metadataUpdatesMu sync.Mutex
	metadataUpdates   map[updatesListener]struct{}

	connectionErrors chan error
	messagesToUser   chan string
	notifyMainThread chan struct{}
	playTokenLost    chan struct{}

	// rawLogMessages is the first place where all log messages ends up, and
	// later once parsed they're moved to the logMessage channel which is
	// exposed.
	rawLogMessages chan string
	logMessages    chan *LogMessage

	endOfTrack      chan struct{}
	streamingErrors chan error

	userInfoUpdatesMu sync.Mutex
	userInfoUpdates   map[updatesListener]struct{}

	offlineStatusUpdates chan struct{}
	offlineErrors        chan error
	credentialsBlobs     chan []byte
	connectionStates     chan struct{}

	scrobbleErrors        chan error
	privateSessionChanges chan bool

	audioConsumer AudioConsumer

	wg       sync.WaitGroup
	dealloc  sync.Once
	shutdown chan struct{}
}

// sessionCall maps the C Spotify session structure to the Go session and
// executes the given function.
func sessionCall(spSession unsafe.Pointer, callback func(*Session)) {
	s := (*C.sp_session)(spSession)
	session := (*Session)(C.sp_session_userdata(s))
	callback(session)
}

// NewSession creates a new session based on the given configuration.
func NewSession(config *Config) (*Session, error) {
	session := &Session{
		shutdown: make(chan struct{}),

		// Event channels, same order as api.h
		loggedIn:  make(chan error, 1),
		loggedOut: make(chan struct{}, 1),

		metadataUpdates: make(map[updatesListener]struct{}),

		connectionErrors: make(chan error, 1),
		messagesToUser:   make(chan string, 1),
		notifyMainThread: make(chan struct{}, 1),
		playTokenLost:    make(chan struct{}, 1),

		rawLogMessages: make(chan string, 128),
		logMessages:    make(chan *LogMessage, 128),

		endOfTrack:      make(chan struct{}, 1),
		streamingErrors: make(chan error, 1),

		userInfoUpdates: make(map[updatesListener]struct{}),

		offlineStatusUpdates: make(chan struct{}, 1),
		offlineErrors:        make(chan error, 1),
		credentialsBlobs:     make(chan []byte, 1),
		connectionStates:     make(chan struct{}, 1),

		scrobbleErrors:        make(chan error, 1),
		privateSessionChanges: make(chan bool, 1),

		audioConsumer: config.AudioConsumer,
	}

	if err := session.setupConfig(config); err != nil {
		return nil, err
	}

	// libspotify expects certain methods to be called from the same thread as was
	// used when the sp_session_create was called. Hence we do lock down one
	// thread to only process events and some of these special calls.
	//
	// AFAIK this is the only way we can decide which thread a given goroutine
	// executes on.
	errc := make(chan error, 1)
	go func() {
		// TODO make sure we have enough threads available
		runtime.LockOSThread()

		err := spError(C.sp_session_create(&session.config, &session.sp_session))
		errc <- err
		if err != nil {
			return
		}
		session.processEvents()
	}()

	if err := <-errc; err != nil {
		return nil, err
	}

	go session.processBackground()

	return session, nil
}

// setupConfig sets the config up to be used when connecting the session.
func (s *Session) setupConfig(config *Config) error {
	if config.ApplicationKey == nil {
		return ErrMissingApplicationKey
	}

	s.config.api_version = C.SPOTIFY_API_VERSION

	s.config.cache_location = C.CString(config.CacheLocation)
	if s.config.cache_location == nil {
		return syscall.ENOMEM
	}

	s.config.settings_location = C.CString(config.SettingsLocation)
	if s.config.settings_location == nil {
		return syscall.ENOMEM
	}

	appKey := C.CString(string(config.ApplicationKey))
	s.config.application_key = unsafe.Pointer(appKey)
	if s.config.application_key == nil {
		return syscall.ENOMEM
	}
	s.config.application_key_size = C.size_t(len(config.ApplicationKey))

	userAgent := config.UserAgent
	if len(userAgent) == 0 {
		userAgent = "go-libspotify"
		if len(config.ApplicationName) > 0 {
			userAgent += "/" + config.ApplicationName
		}
	}
	s.config.user_agent = C.CString(userAgent)
	if s.config.user_agent == nil {
		return syscall.ENOMEM
	}

	// Setup the callbacks structure used for all sessions. The difference
	// between each session object is the userdata object which points into the
	// Go Session object.
	once.Do(func() { C.set_callbacks(&callbacks) })
	s.config.callbacks = &callbacks
	s.config.userdata = unsafe.Pointer(s)

	if config.CompressPlaylists {
		s.config.compress_playlists = 1
	}
	if config.DisablePlaylistMetadataCache {
		s.config.dont_save_metadata_for_playlists = 1
	}
	if config.InitiallyUnloadPlaylists {
		s.config.initially_unload_playlists = 1
	}
	return nil
}

func (s *Session) free() {
	if s.config.cache_location != nil {
		C.free(unsafe.Pointer(s.config.cache_location))
		s.config.cache_location = nil
	}
	if s.config.settings_location != nil {
		C.free(unsafe.Pointer(s.config.settings_location))
		s.config.settings_location = nil
	}
	if s.config.application_key != nil {
		C.free(unsafe.Pointer(s.config.application_key))
		s.config.application_key = nil
	}
	if s.config.user_agent != nil {
		C.free(unsafe.Pointer(s.config.user_agent))
		s.config.user_agent = nil
	}
}

// Close closes the session, making the session unusable for any future calls.
// This call releases the session internally back to libspotify and shuts the
// background processing thread down.
func (s *Session) Close() error {
	var err error
	s.dealloc.Do(func() {
		// Send shutdown events to log and event processor
		s.shutdown <- struct{}{}
		s.shutdown <- struct{}{}
		s.wg.Wait()

		err = spError(C.sp_session_release(s.sp_session))
		s.free()
	})
	return nil
}

// Login logs the the specified username and password combo. This
// initiates the login in the background.
//
// An application MUST NEVER store the user's password in clear
// text. If automatic relogin is required, use Relogin.
func (s *Session) Login(c Credentials, remember bool) error {
	cusername := C.CString(c.Username)
	defer C.free(unsafe.Pointer(cusername))
	var crememberme C.bool = 0
	if remember {
		crememberme = 1
	}
	var cpassword, cblob *C.char
	if len(c.Password) > 0 {
		cpassword = C.CString(c.Password)
		defer C.free(unsafe.Pointer(cpassword))
	}
	if len(c.Blob) > 0 {
		cblob = C.CString(string(c.Blob))
		defer C.free(unsafe.Pointer(cblob))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	rc := C.sp_session_login(
		s.sp_session,
		cusername,
		cpassword,
		crememberme,
		cblob,
	)
	return spError(rc)
}

// Relogin logs the remembered user in if the last user which logged in, logged
// in with the remember flag set to true.
//
// If no credentials are stored, this will return ErrNoCredentials.
func (s *Session) Relogin() error {
	return spError(C.sp_session_relogin(s.sp_session))
}

func (s *Session) RememberedUser() string {
	size := C.sp_session_remembered_user(s.sp_session, nil, 0)
	buf := (*C.char)(C.malloc(C.size_t(size) + 1))
	if buf == nil {
		panic("spotify: failed to allocate memory")
	}
	defer C.free(unsafe.Pointer(buf))
	C.sp_session_remembered_user(s.sp_session, buf, C.size_t(size)+1)
	return C.GoString(buf)
}

// LoginUsername returns the user's login username.
func (s *Session) LoginUsername() string {
	return C.GoString(C.sp_session_user_name(s.sp_session))
}

// ForgetMe removes any stored credentials. If no credentials are currently
// stored, nothing will happen.
func (s *Session) ForgetMe() error {
	return spError(C.sp_session_forget_me(s.sp_session))
}

// CurrentUser returns a user object for the currently logged in user.
func (s *Session) CurrentUser() (*User, error) {
	sp_user := C.sp_session_user(s.sp_session)
	if sp_user == nil {
		return nil, errors.New("spotify: no user logged in")
	}
	return newUser(s, sp_user), nil
}

func (s *Session) GetUser(username string) (*User, error) {
	uri := "spotify:user:" + url.QueryEscape(username)
	link, err := s.ParseLink(uri)
	if err != nil {
		return nil, err
	}

	return link.User()
}

// Logout logs the currently logged in user out
//
// Always call this before terminating the application and
// libspotify is currently logged in. Otherwise, the settings and
// cache may be lost.
func (s *Session) Logout() error {
	return spError(C.sp_session_logout(s.sp_session))
}

// FlushCaches makes libspotify write all data that is meant to
// be stored on disk to the disk immediately. libspotify does this
// periodically by itself and also on logout. Under normal
// conditions this shouldn't be needed.
func (s *Session) FlushCaches() error {
	return spError(C.sp_session_flush_caches(s.sp_session))
}

// SetAudioConsumer sets the audio consumer.
func (s *Session) SetAudioConsumer(c AudioConsumer) {
	s.audioConsumer = c
}

// ConnectionState returns the current connection state for the
// session.
func (s *Session) ConnectionState() ConnectionState {
	state := C.sp_session_connectionstate(s.sp_session)
	return ConnectionState(state)
}

// SetCacheSize sets the maximum cache size in megabytes.
//
// Setting it to 0 (the default) will let libspotify automatically resize the
// cache (10% of disk free space).
func (s *Session) SetCacheSize(size int) {
	C.sp_session_set_cache_size(s.sp_session, C.size_t(size))
}

func (s *Session) Player() *Player {
	return &Player{s}
}

type Bitrate C.sp_bitrate

const (
	Bitrate96k  = Bitrate(C.SP_BITRATE_96k)
	Bitrate160k = Bitrate(C.SP_BITRATE_160k)
	Bitrate320k = Bitrate(C.SP_BITRATE_320k)
)

type SampleType C.sp_sampletype

const (
	// 16-bit signed integer samples
	SampleTypeInt16NativeEndian = SampleType(C.SP_SAMPLETYPE_INT16_NATIVE_ENDIAN)
)

type AudioFormat struct {
	// Sample type
	SampleType SampleType

	// Audio sample rate, in samples per second.
	SampleRate int

	// Number of channels. Currently 1 or 2.
	Channels int
}

func (af AudioFormat) Equal(u AudioFormat) bool {
	return af.SampleType == u.SampleType &&
		af.SampleRate == u.SampleRate &&
		af.Channels == u.Channels
}

func cbool(b bool) C.bool {
	if b {
		return 1
	} else {
		return 0
	}
}

func (s *Session) PreferredBitrate(bitrate Bitrate) error {
	return spError(C.sp_session_preferred_bitrate(
		s.sp_session, C.sp_bitrate(bitrate),
	))
}

func (s *Session) PreferredOfflineBitrate(bitrate Bitrate, resync bool) error {
	return spError(C.sp_session_preferred_offline_bitrate(
		s.sp_session, C.sp_bitrate(bitrate), cbool(resync),
	))
}

func (s *Session) VolumeNormalization() bool {
	return C.sp_session_get_volume_normalization(s.sp_session) == 1
}

func (s *Session) SetVolumeNormalization(normalize bool) {
	C.sp_session_set_volume_normalization(s.sp_session, cbool(normalize))
}

func (s *Session) Playlists() (*PlaylistContainer, error) {
	return newPlaylistContainer(s)
}

func (s *Session) Starred() *Playlist {
	sp_playlist := C.sp_session_starred_create(s.sp_session)
	return newPlaylist(s, sp_playlist, true)
}

func (s *Session) PrivateSession() bool {
	return C.sp_session_is_private_session(s.sp_session) == 1
}

func (s *Session) SetPrivateSession(private bool) {
	C.sp_session_set_private_session(s.sp_session, cbool(private))
}

type SocialProvider C.sp_social_provider

const (
	SocialProviderSpotify  = SocialProvider(C.SP_SOCIAL_PROVIDER_SPOTIFY)
	SocialProviderFacebook = SocialProvider(C.SP_SOCIAL_PROVIDER_FACEBOOK)
	SocialProviderLastFM   = SocialProvider(C.SP_SOCIAL_PROVIDER_LASTFM)
)

type ScrobblingState C.sp_scrobbling_state

const (
	ScrobblingStateUseGlobalSetting = ScrobblingState(C.SP_SCROBBLING_STATE_USE_GLOBAL_SETTING)
	ScrobblingStateLocalEnabled     = ScrobblingState(C.SP_SCROBBLING_STATE_LOCAL_ENABLED)
	ScrobblingStateLocalDisabled    = ScrobblingState(C.SP_SCROBBLING_STATE_LOCAL_DISABLED)
	ScrobblingStateGlobalEnabled    = ScrobblingState(C.SP_SCROBBLING_STATE_GLOBAL_ENABLED)
	ScrobblingStateGlobalDisabled   = ScrobblingState(C.SP_SCROBBLING_STATE_GLOBAL_DISABLED)
)

func (s *Session) Scrobbling(provider SocialProvider) (ScrobblingState, error) {
	var state C.sp_scrobbling_state
	err := spError(C.sp_session_is_scrobbling(
		s.sp_session, C.sp_social_provider(provider), &state,
	))
	return ScrobblingState(state), err
}

func (s *Session) SetScrobbling(provider SocialProvider, state ScrobblingState) error {
	return spError(C.sp_session_set_scrobbling(
		s.sp_session, C.sp_social_provider(provider), C.sp_scrobbling_state(state),
	))
}

func (s *Session) IsScrobblingPossible(provider SocialProvider) bool {
	var possible C.bool
	C.sp_session_is_scrobbling_possible(
		s.sp_session, C.sp_social_provider(provider), &possible,
	)
	return possible == 1
}

type ConnectionType C.sp_connection_type

const (
	// Connection type unknown (Default)
	ConnectionTypeUnknown = ConnectionType(C.SP_CONNECTION_TYPE_UNKNOWN)
	// No connection
	ConnectionTypeNone = ConnectionType(C.SP_CONNECTION_TYPE_NONE)
	// Mobile data (EDGE, 3G, etc)
	ConnectionTypeMobile = ConnectionType(C.SP_CONNECTION_TYPE_MOBILE)
	// Roamed mobile data (EDGE, 3G, etc)
	ConnectionTypeMobileRoaming = ConnectionType(C.SP_CONNECTION_TYPE_MOBILE_ROAMING)
	// Wireless connection
	ConnectionTypeWifi = ConnectionType(C.SP_CONNECTION_TYPE_WIFI)
	// Ethernet cable, etc
	ConnectionTypeWired = ConnectionType(C.SP_CONNECTION_TYPE_WIRED)
)

func (s *Session) SetConnectionType(t ConnectionType) {
	C.sp_session_set_connection_type(s.sp_session, C.sp_connection_type(t))
}

type ConnectionRules struct {
	Network          bool
	NetworkIfRoaming bool
	SyncOverMobile   bool
	SyncOverWifi     bool
}

func (s *Session) SetConnectionRules(r ConnectionRules) {
	var rules C.sp_connection_rules
	if r.Network {
		rules |= C.SP_CONNECTION_RULE_NETWORK
	}
	if r.NetworkIfRoaming {
		rules |= C.SP_CONNECTION_RULE_NETWORK_IF_ROAMING
	}
	if r.SyncOverMobile {
		rules |= C.SP_CONNECTION_RULE_ALLOW_SYNC_OVER_MOBILE
	}
	if r.SyncOverWifi {
		rules |= C.SP_CONNECTION_RULE_ALLOW_SYNC_OVER_WIFI
	}
	C.sp_session_set_connection_rules(s.sp_session, rules)
}

func (s *Session) OfflineTracksToSync() int {
	return int(C.sp_offline_tracks_to_sync(s.sp_session))
}

func (s *Session) OfflinePlaylists() int {
	return int(C.sp_offline_num_playlists(s.sp_session))
}

type OfflineSyncStatus struct {
	sp_status C.sp_offline_sync_status
}

func (oss *OfflineSyncStatus) QueuedTracks() int {
	return int(oss.sp_status.queued_tracks)
}

func (oss *OfflineSyncStatus) QueuedBytes() int {
	return int(oss.sp_status.queued_bytes)
}

func (oss *OfflineSyncStatus) DoneTracks() int {
	return int(oss.sp_status.done_tracks)
}

func (oss *OfflineSyncStatus) DoneBytes() int {
	return int(oss.sp_status.done_bytes)
}

func (oss *OfflineSyncStatus) CopiedTracks() int {
	return int(oss.sp_status.copied_tracks)
}

func (oss *OfflineSyncStatus) CopiedBytes() int {
	return int(oss.sp_status.copied_bytes)
}

func (oss *OfflineSyncStatus) WillNotCopyTracks() int {
	return int(oss.sp_status.willnotcopy_tracks)
}

func (oss *OfflineSyncStatus) ErrorTracks() int {
	return int(oss.sp_status.error_tracks)
}

func (oss *OfflineSyncStatus) Synching() bool {
	return oss.sp_status.syncing == 1
}

func (s *Session) OfflineSyncStatus() (*OfflineSyncStatus, error) {
	status := &OfflineSyncStatus{}
	synching := C.sp_offline_sync_get_status(s.sp_session, &status.sp_status)
	if synching == 0 {
		return nil, errors.New("spotify: no sync in progress")
	}
	return status, nil
}

func (s *Session) OfflineTimeLeft() time.Duration {
	seconds := C.sp_offline_time_left(s.sp_session)
	return time.Duration(seconds) * time.Second
}

func (s *Session) Region() Region {
	return Region(C.sp_session_user_country(s.sp_session))
}

func (s *Session) ArtistsToplist(region ToplistRegion) *ArtistsToplist {
	return newArtistsToplist(s, region, nil)
}

func (s *Session) AlbumsToplist(region ToplistRegion) *AlbumsToplist {
	return newAlbumsToplist(s, region, nil)
}

func (s *Session) TracksToplist(region ToplistRegion) *TracksToplist {
	return newTracksToplist(s, region, nil)
}

// LoggedInUpdates returns a channel used to get notified when the
// login has been processed.
func (s *Session) LoggedInUpdates() <-chan error {
	return s.loggedIn
}

// LoggedOutUpdates returns a channel used to get notified when the
// session has been logged out.
func (s *Session) LoggedOutUpdates() <-chan struct{} {
	return s.loggedOut
}

// ConnectionErrorUpdates returns a channel containing connection errors.
func (s *Session) ConnectionErrorUpdates() <-chan error {
	return s.connectionErrors
}

// MessagesToUser returns a channel containing messages which the access point
// wants to display to a user.
//
// In the desktop client, these are shown in a blueish toolbar just below the
// search box.
func (s *Session) MessagesToUser() <-chan string {
	return s.messagesToUser
}

// PlayTokenLostUpdates returns a channel used to get updates
// when user loses the play token.
func (s *Session) PlayTokenLostUpdates() <-chan struct{} {
	return s.playTokenLost
}

// LogMessages returns a channel used to get log messages.
func (s *Session) LogMessages() <-chan *LogMessage {
	return s.logMessages
}

// EndOfTrackUpdates returns a channel used to get updates
// when a track ends playing
func (s *Session) EndOfTrackUpdates() <-chan struct{} {
	return s.endOfTrack
}

// StreamingErrors returns a channel with streaming errors.
func (s *Session) StreamingErrors() <-chan error {
	return s.streamingErrors
}

// OfflineStatusUpdates returns a channel containing
// offline synchronization status updates.
func (s *Session) OfflineStatusUpdates() <-chan struct{} {
	return s.offlineStatusUpdates
}

// TODO document the difference between these functions

// OfflineErrors returns a channel containing offline
// synchronization status status updates.
func (s *Session) OfflineErrors() <-chan error {
	return s.offlineErrors
}

// CredentialsBlobUpdates returns a channel used to get updates
// for credential blobs.
func (s *Session) CredentialsBlobUpdates() <-chan []byte {
	return s.credentialsBlobs
}

// ConnectionStateUpdates returns a channel used to get updates on
// the connection state.
func (s *Session) ConnectionStateUpdates() <-chan struct{} {
	return s.connectionStates
}

// ScrobbleErrors returns a channel with scrobble errors.
//
// Called when there is a scrobble error event.
func (s *Session) ScrobbleErrors() <-chan error {
	return s.scrobbleErrors
}

// PrivateSessionModeChanges returns a channel where
// private session changes are published.
//
// If the value is true, the user is in private mode.
func (s *Session) PrivateSessionModeChanges() <-chan bool {
	return s.privateSessionChanges
}

type SearchType C.sp_search_type

const (
	SearchStandard SearchType = SearchType(C.SP_SEARCH_STANDARD)
	SearchSuggest             = SearchType(C.SP_SEARCH_SUGGEST)
)

type SearchSpec struct {
	// Search result offset
	Offset int

	// Search result limitation
	Count int
}

// SearchOptions contains offsets and limits for the search query.
type SearchOptions struct {
	// Tracks is the number of tracks to search for
	Tracks SearchSpec

	// Albums is the number of albums to search for
	Albums SearchSpec

	// Artists is the number of artists to search for
	Artists SearchSpec

	// Playlist is the number of playlists to search for
	Playlists SearchSpec

	// Type is the search type. Defaults to normal searching.
	Type SearchType
}

// Search searches Spotify for track, album, artist and / or playlists.
func (s *Session) Search(query string, opts *SearchOptions) (*Search, error) {
	return newSearch(s, query, opts)
}

// ParseLink parses a Spotify URI / URL string.
func (s *Session) ParseLink(link string) (*Link, error) {
	clink := C.CString(link)
	defer C.free(unsafe.Pointer(clink))
	sp_link := C.sp_link_create_from_string(clink)
	if sp_link == nil {
		return nil, errors.New("spotify: invalid spotify link")
	}
	return newLink(s, sp_link, false), nil
}

// SetStarred is used to star/unstar a set of tracks.
// func (s *Session) SetStarred(tracks []*Track, star bool) {
// 	sp_tracks := (**C.sp_track)(C.malloc(C.size_t(len(tracks))))
// 	defer C.free(unsafe.Pointer(sp_tracks))
//
// 	for i, track := range tracks {
// 		sp_tracks[i] = track.sp_track
// 	}
//
// 	C.sp_track_set_starred(
// 		s.sp_session, sp_tracks, C.int(len(tracks)), cbool(star),
// 	)
// }

func (s *Session) log(level LogLevel, message string) {
	m := &LogMessage{time.Now(), level, "go-libspotify", message}
	select {
	case s.logMessages <- m:
	default:
	}
}

func (s *Session) processEvents() {
	s.wg.Add(1)
	defer s.wg.Done()

	var nextTimeoutMs C.int
	for {
		s.mu.Lock()
		rc := C.sp_session_process_events(s.sp_session, &nextTimeoutMs)
		s.mu.Unlock()
		if err := spError(rc); err != nil {
			println("process error err", err)
			continue
		}

		timeout := time.Duration(nextTimeoutMs) * time.Millisecond
		select {
		case <-time.After(timeout):
		case <-s.notifyMainThread:
		case <-s.shutdown:
			return
		}
	}
}

func (s *Session) processBackground() {
	s.wg.Add(1)
	defer s.wg.Done()

	for {
		select {
		case message := <-s.rawLogMessages:
			m, err := parseLogMessage(message)
			if m != nil {
				select {
				case s.logMessages <- m:
				default:
				}
			}
			if err != nil {
				s.log(LogWarning, err.Error()+": "+message)
			}
		case <-s.shutdown:
			return
		}
	}
}

type updatesListener interface {
	cbUpdated()
}

func (s *Session) listenForMetadataUpdates(checkIfLoaded func() bool, l updatesListener) bool {
	return s.listenForUpdates(&s.metadataUpdatesMu, s.metadataUpdates, checkIfLoaded, l)
}

func (s *Session) stopListenForMetadataUpdates(l updatesListener) {
	s.stopListenForUpdates(&s.metadataUpdatesMu, s.metadataUpdates, l)
}

func (s *Session) listenForUserInfoUpdates(checkIfLoaded func() bool, l updatesListener) bool {
	return s.listenForUpdates(&s.userInfoUpdatesMu, s.userInfoUpdates, checkIfLoaded, l)
}

func (s *Session) stopListenForUserInfoUpdates(l updatesListener) {
	s.stopListenForUpdates(&s.userInfoUpdatesMu, s.userInfoUpdates, l)
}

func (s *Session) listenForUpdates(mu *sync.Mutex, m map[updatesListener]struct{}, checkIfLoaded func() bool, l updatesListener) bool {
	var added bool
	mu.Lock()
	defer mu.Unlock()
	if !checkIfLoaded() {
		m[l] = struct{}{}
		added = true
	}
	return added
}

func (s *Session) stopListenForUpdates(mu *sync.Mutex, m map[updatesListener]struct{}, l updatesListener) {
	mu.Lock()
	defer mu.Unlock()
	delete(m, l)
}

func (s *Session) sendUpdates(mu *sync.Mutex, m map[updatesListener]struct{}) {
	mu.Lock()
	defer mu.Unlock()
	for l := range m {
		l.cbUpdated()
	}
}

func (s *Session) cbLoggedIn(err error) {
	select {
	case s.loggedIn <- err:
	default:
		println("failed to send logged in event")
	}
}

func (s *Session) cbLoggedOut() {
	select {
	case s.loggedOut <- struct{}{}:
	default:
		println("failed to send logged out event")
	}
}

func (s *Session) cbMetadataUpdated() {
	s.sendUpdates(&s.metadataUpdatesMu, s.metadataUpdates)
}

func (s *Session) cbConnectionError(err error) {
	select {
	case s.connectionErrors <- err:
	default:
	}
}

func (s *Session) cbMessagesToUser(message string) {
	select {
	case s.messagesToUser <- message:
	default:
	}
}

func (s *Session) cbNotifyMainThread() {
	select {
	case s.notifyMainThread <- struct{}{}:
	default:
		println("failed to notify main thread")
		// TODO generate (internal) log message
	}
}

// cbMusicDelivery is called when there is decompressed audio data available.
// NOTE: This function must never block.
func (s *Session) cbMusicDelivery(format AudioFormat, frames []byte) int {
	if s.audioConsumer == nil {
		return 0
	}
	return s.audioConsumer.WriteAudio(format, frames)
}

func (s *Session) cbPlayTokenLost() {
	select {
	case s.playTokenLost <- struct{}{}:
	default:
	}
}

func (s *Session) cbLogMessage(message string) {
	select {
	case s.rawLogMessages <- message:
	default:
	}
}

func (s *Session) cbEndOfTrack() {
	select {
	case s.endOfTrack <- struct{}{}:
	default:
	}
}

func (s *Session) cbStreamingError(err error) {
	select {
	case s.streamingErrors <- err:
	default:
	}
}

func (s *Session) cbUserInfoUpdated() {
	s.sendUpdates(&s.userInfoUpdatesMu, s.userInfoUpdates)
}

func (s *Session) cbStartPlayback() {
	println("start playback")
}

func (s *Session) cbStopPlayback() {
	println("stop playback")
}

func (s *Session) cbGetAudioBufferStats() {
	println("get audio buffer stats")
}

func (s *Session) cbOfflineStatusUpdated() {
	select {
	case s.offlineStatusUpdates <- struct{}{}:
	default:
	}
}

func (s *Session) cbOfflineError(err error) {
	select {
	case s.offlineErrors <- err:
	default:
	}
}

func (s *Session) cbCredentialsBlobUpdated(blob []byte) {
	select {
	case s.credentialsBlobs <- blob:
	default:
	}
}

func (s *Session) cbConnectionStateUpdated() {
	select {
	case s.connectionStates <- struct{}{}:
	default:
	}
}

func (s *Session) cbScrobbleError(err error) {
	select {
	case s.scrobbleErrors <- err:
	default:
	}
}

func (s *Session) cbPrivateSessionModeChanged(private bool) {
	select {
	case s.privateSessionChanges <- private:
	default:
	}
}

//export go_logged_in
func go_logged_in(spSession unsafe.Pointer, spErr C.sp_error) {
	sessionCall(spSession, func(s *Session) {
		s.cbLoggedIn(spError(spErr))
	})
}

//export go_logged_out
func go_logged_out(spSession unsafe.Pointer) {
	sessionCall(spSession, (*Session).cbLoggedOut)
}

//export go_metadata_updated
func go_metadata_updated(spSession unsafe.Pointer) {
	sessionCall(spSession, (*Session).cbMetadataUpdated)
}

//export go_connection_error
func go_connection_error(spSession unsafe.Pointer, spErr C.sp_error) {
	sessionCall(spSession, func(s *Session) {
		s.cbConnectionError(spError(spErr))
	})
}

//export go_message_to_user
func go_message_to_user(spSession unsafe.Pointer, message *C.char) {
	sessionCall(spSession, func(s *Session) {
		s.cbMessagesToUser(C.GoString(message))
	})
}

//export go_notify_main_thread
func go_notify_main_thread(spSession unsafe.Pointer) {
	sessionCall(spSession, (*Session).cbNotifyMainThread)
}

//export go_music_delivery
func go_music_delivery(spSession unsafe.Pointer, format *C.sp_audioformat, data unsafe.Pointer, num_frames C.int) C.int {
	s := (*C.sp_session)(spSession)
	session := (*Session)(C.sp_session_userdata(s))
	audioFormat := AudioFormat{
		SampleType(format.sample_type),
		int(format.sample_rate),
		int(format.channels),
	}
	// TODO optimize allocation
	var frames []byte
	switch audioFormat.SampleType {
	case SampleTypeInt16NativeEndian:
		frames = C.GoBytes(data, 2*num_frames*format.channels)
	default:
		panic("Unsupported sample type")
	}
	return C.int(session.cbMusicDelivery(audioFormat, frames))
}

//export go_play_token_lost
func go_play_token_lost(spSession unsafe.Pointer) {
	sessionCall(spSession, (*Session).cbPlayTokenLost)
}

//export go_log_message
func go_log_message(spSession unsafe.Pointer, message *C.char) {
	sessionCall(spSession, func(s *Session) {
		s.cbLogMessage(C.GoString(message))
	})
}

//export go_end_of_track
func go_end_of_track(spSession unsafe.Pointer) {
	sessionCall(spSession, (*Session).cbEndOfTrack)
}

//export go_streaming_error
func go_streaming_error(spSession unsafe.Pointer, err C.sp_error) {
	sessionCall(spSession, func(s *Session) {
		s.cbStreamingError(spError(err))
	})
}

//export go_userinfo_updated
func go_userinfo_updated(spSession unsafe.Pointer) {
	sessionCall(spSession, (*Session).cbUserInfoUpdated)
}

//export go_start_playback
func go_start_playback(spSession unsafe.Pointer) {
	sessionCall(spSession, (*Session).cbStartPlayback)
}

//export go_stop_playback
func go_stop_playback(spSession unsafe.Pointer) {
	sessionCall(spSession, (*Session).cbStopPlayback)
}

//export go_get_audio_buffer_stats
func go_get_audio_buffer_stats(spSession unsafe.Pointer, stats *C.sp_audio_buffer_stats) {
	sessionCall(spSession, func(s *Session) {
		// TODO make some translation here, pass in stats
		s.cbGetAudioBufferStats()
	})
}

//export go_offline_status_updated
func go_offline_status_updated(spSession unsafe.Pointer) {
	sessionCall(spSession, (*Session).cbOfflineStatusUpdated)
}

//export go_offline_error
func go_offline_error(spSession unsafe.Pointer, err C.sp_error) {
	sessionCall(spSession, func(s *Session) {
		s.cbOfflineError(spError(err))
	})
}

//export go_credentials_blob_updated
func go_credentials_blob_updated(spSession unsafe.Pointer, data *C.char) {
	sessionCall(spSession, func(s *Session) {
		// We keep the blob as []byte instead of string because it just makes more
		// sense than how libspotify does it.
		blob := []byte(C.GoString(data))
		s.cbCredentialsBlobUpdated(blob)
	})
}

//export go_connectionstate_updated
func go_connectionstate_updated(spSession unsafe.Pointer) {
	sessionCall(spSession, (*Session).cbConnectionStateUpdated)
}

//export go_scrobble_error
func go_scrobble_error(spSession unsafe.Pointer, err C.sp_error) {
	sessionCall(spSession, func(s *Session) {
		s.cbScrobbleError(spError(err))
	})
}

//export go_private_session_mode_changed
func go_private_session_mode_changed(spSession unsafe.Pointer, is_private C.bool) {
	sessionCall(spSession, func(s *Session) {
		s.cbPrivateSessionModeChanged(is_private == 1)
	})
}

//export go_search_complete
func go_search_complete(spSearch unsafe.Pointer, userdata unsafe.Pointer) {
	s := (*Search)(userdata)
	s.cbComplete()
}

//export go_toplistbrowse_complete
func go_toplistbrowse_complete(sp_toplistsearch unsafe.Pointer, userdata unsafe.Pointer) {
	// TODO find a nicer way to do this
	t := (*toplist)(userdata)
	switch t.ttype {
	case toplistTypeArtists:
		((*ArtistsToplist)(userdata)).cbComplete()
	case toplistTypeAlbums:
		((*AlbumsToplist)(userdata)).cbComplete()
	case toplistTypeTracks:
		((*TracksToplist)(userdata)).cbComplete()
	default:
		panic("spotify: unhandled toplist type")
	}
}

// AudioConsumer is the interface used to deliver music. The data delivered
// will be available as []byte and the format contains information about it.
type AudioConsumer interface {
	WriteAudio(AudioFormat, []byte) int
}

type Player struct {
	s *Session
}

func (p *Player) Load(t *Track) error {
	return spError(C.sp_session_player_load(p.s.sp_session, t.sp_track))
}

func (p *Player) Seek(offset time.Duration) {
	ms := C.int(offset / time.Millisecond)
	C.sp_session_player_seek(p.s.sp_session, ms)
}

func (p *Player) Play() {
	C.sp_session_player_play(p.s.sp_session, 1)
}

func (p *Player) Pause() {
	C.sp_session_player_play(p.s.sp_session, 0)
}

func (p *Player) Unload() {
	C.sp_session_player_unload(p.s.sp_session)
}

func (p *Player) Prefetch(t *Track) error {
	return spError(C.sp_session_player_prefetch(p.s.sp_session, t.sp_track))
}

type PlaylistType C.sp_playlist_type

const (
	// A normal playlist.
	PlaylistTypePlaylist = PlaylistType(C.SP_PLAYLIST_TYPE_PLAYLIST)

	// Marks a folder's starting point
	PlaylistTypeStartFolder = PlaylistType(C.SP_PLAYLIST_TYPE_START_FOLDER)

	// Marks previous folder's ending point
	PlaylistTypeEndFolder = PlaylistType(C.SP_PLAYLIST_TYPE_END_FOLDER)

	// Placeholder
	PlaylistTypePlaceholder = PlaylistType(C.SP_PLAYLIST_TYPE_PLACEHOLDER)
)

type PlaylistContainer struct {
	session *Session

	sp_playlistcontainer *C.sp_playlistcontainer
	callbacks            C.sp_playlistcontainer_callbacks

	mu      sync.Mutex
	folders map[uint64]*PlaylistFolder

	wg     sync.WaitGroup
	loaded chan struct{}
}

func newPlaylistContainer(s *Session) (*PlaylistContainer, error) {
	pc := &PlaylistContainer{
		session: s,
		loaded:  make(chan struct{}, 1),
		folders: make(map[uint64]*PlaylistFolder),
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.sp_playlistcontainer = C.sp_session_playlistcontainer(s.sp_session)
	if pc.sp_playlistcontainer == nil {
		return nil, errors.New("spotify: failed to get playlist container")
	}

	if pc.isLoaded() {
		pc.loaded <- struct{}{}
	} else {
		pc.wg.Add(1)
	}

	C.sp_playlistcontainer_add_ref(pc.sp_playlistcontainer)
	runtime.SetFinalizer(pc, (*PlaylistContainer).release)
	C.set_playlistcontainer_callbacks(&pc.callbacks)
	C.sp_playlistcontainer_add_callbacks(pc.sp_playlistcontainer, &pc.callbacks, unsafe.Pointer(pc))

	return pc, nil
}

func (pc *PlaylistContainer) release() {
	if pc.sp_playlistcontainer == nil {
		panic("spotify: playlist container object has no sp_playlistcontainer object")
	}
	C.sp_playlistcontainer_remove_callbacks(pc.sp_playlistcontainer, &pc.callbacks, unsafe.Pointer(pc))
	C.sp_playlistcontainer_release(pc.sp_playlistcontainer)
	pc.sp_playlistcontainer = nil
}

func (pc *PlaylistContainer) Owner() (*User, error) {
	sp_user := C.sp_playlistcontainer_owner(pc.sp_playlistcontainer)
	if sp_user == nil {
		return nil, errors.New("spotify: unknown user")
	}
	return newUser(pc.session, sp_user), nil
}

// TODO rename to Entries?
func (pc *PlaylistContainer) Playlists() int {
	return int(C.sp_playlistcontainer_num_playlists(pc.sp_playlistcontainer))
}

// TODO rename to EntryType?
func (pc *PlaylistContainer) PlaylistType(n int) PlaylistType {
	if n < 0 || n >= pc.Playlists() {
		panic("spotify: playlist out of range")
	}
	return PlaylistType(C.sp_playlistcontainer_playlist_type(pc.sp_playlistcontainer, C.int(n)))
}

func (pc *PlaylistContainer) Folder(n int) (*PlaylistFolder, error) {
	// if pc.PlaylistType(n) != PlaylistTypeStartFolder
	folderId := uint64(C.sp_playlistcontainer_playlist_folder_id(pc.sp_playlistcontainer, C.int(n)))
	if folderId == 0 {
		return nil, errors.New("spotify: not a folder")
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()
	if f := pc.folders[folderId]; f != nil {
		return f, nil
	}

	f := newPlaylistFolder(pc, n, folderId)
	pc.folders[folderId] = f
	return f, nil
}

func (pc *PlaylistContainer) Playlist(n int) *Playlist {
	var sp_playlist *C.sp_playlist
	switch pc.PlaylistType(n) {
	case PlaylistTypePlaceholder:
		fallthrough
	case PlaylistTypePlaylist:
		sp_playlist = C.sp_playlistcontainer_playlist(pc.sp_playlistcontainer, C.int(n))
	default:
		panic("spotify: index does not hold a playlist entry")
	}
	return newPlaylist(pc.session, sp_playlist, false)
}

func (pc *PlaylistContainer) isLoaded() bool {
	return C.sp_playlistcontainer_is_loaded(pc.sp_playlistcontainer) == 1
}

func (pc *PlaylistContainer) Wait() {
	pc.wg.Wait()
}

func (pc *PlaylistContainer) cbLoaded() {
	println("playlist container loaded")
	select {
	case pc.loaded <- struct{}{}:
		pc.wg.Done()
	}
}

//export go_playlistcontainer_playlist_added
func go_playlistcontainer_playlist_added(sp_playlistcontainer unsafe.Pointer, sp_playlist unsafe.Pointer, position C.int, userdata unsafe.Pointer) {
	println("playlist container playlist added")
}

//export go_playlistcontainer_loaded
func go_playlistcontainer_loaded(sp_playlistcontainer unsafe.Pointer, userdata unsafe.Pointer) {
	// playlistContainerCall(spSession, (*PlaylistContainer).cbLoaded)
	println("playlistcontainer loaded")
	(*PlaylistContainer)(userdata).cbLoaded()
}

type PlaylistFolder struct {
	pc    *PlaylistContainer
	index int
	id    uint64

	mu   sync.Mutex
	name string
}

func newPlaylistFolder(pc *PlaylistContainer, n int, id uint64) *PlaylistFolder {
	return &PlaylistFolder{pc: pc, index: n, id: id}
}

func (pf *PlaylistFolder) Id() uint64 {
	return pf.id
}

func (pf *PlaylistFolder) Name() string {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if pf.name == "" {
		const bufSize = 256
		buf := (*C.char)(C.malloc(bufSize))
		if buf == nil {
			panic("spotify: failed to allocate buffer")
		}
		defer C.free(unsafe.Pointer(buf))

		rc := C.sp_playlistcontainer_playlist_folder_name(
			pf.pc.sp_playlistcontainer, C.int(pf.index),
			buf, 256,
		)
		if rc != C.SP_ERROR_OK {
			panic("spotify: folder is no longer in range")
		}
		pf.name = C.GoString(buf)
	}
	return pf.name
}

type LinkType C.sp_linktype

const (
	// Link type not valid - default until the library has parsed the link, or
	// when parsing failed
	LinkTypeInvalid = LinkType(C.SP_LINKTYPE_INVALID)
	// Link type is track
	LinkTypeTrack = LinkType(C.SP_LINKTYPE_TRACK)
	// Link type is album
	LinkTypeAlbum = LinkType(C.SP_LINKTYPE_ALBUM)
	// Link type is artist
	LinkTypeArtist = LinkType(C.SP_LINKTYPE_ARTIST)
	// Link type is search
	LinkTypeSearch = LinkType(C.SP_LINKTYPE_SEARCH)
	// Link type is playlist
	LinkTypePlaylist = LinkType(C.SP_LINKTYPE_PLAYLIST)
	// Link type is user
	LinkTypeUser = LinkType(C.SP_LINKTYPE_PROFILE)
	// Link type is starred
	LinkTypeStarred = LinkType(C.SP_LINKTYPE_STARRED)
	// Link type is a local file
	LinkTypeLocalTrack = LinkType(C.SP_LINKTYPE_LOCALTRACK)
	// Link type is an image
	LinkTypeImage = LinkType(C.SP_LINKTYPE_IMAGE)
)

type Link struct {
	session *Session
	sp_link *C.sp_link
}

func newLink(s *Session, sp_link *C.sp_link, incRef bool) *Link {
	if incRef {
		C.sp_link_add_ref(sp_link)
	}
	link := &Link{s, sp_link}
	runtime.SetFinalizer(link, (*Link).release)
	return link
}

func (l *Link) release() {
	if l.sp_link == nil {
		panic("spotify: link object has no sp_link object")
	}
	C.sp_link_release(l.sp_link)
	l.sp_link = nil
}

// String implements the Stringer interface and returns the Link URI.
func (l *Link) String() string {
	// Determine how big string we need and get the string out.
	size := C.sp_link_as_string(l.sp_link, nil, 0)
	buf := (*C.char)(C.malloc(C.size_t(size) + 1))
	if buf == nil {
		return "<invalid>"
	}
	defer C.free(unsafe.Pointer(buf))
	C.sp_link_as_string(l.sp_link, buf, size+1)
	return C.GoString(buf)
}

// LinkType returns the type of link.
func (l *Link) Type() LinkType {
	return LinkType(C.sp_link_type(l.sp_link))
}

func (l *Link) Track() (*Track, error) {
	if l.Type() != LinkTypeTrack {
		return nil, errors.New("spotify: link is not a track")
	}
	return newTrack(l.session, C.sp_link_as_track(l.sp_link)), nil
}

// TrackOffset returns the offset for the track link.
func (l *Link) TrackOffset() time.Duration {
	var offsetMs C.int
	C.sp_link_as_track_and_offset(l.sp_link, &offsetMs)
	return time.Duration(offsetMs) / time.Millisecond
}

func (l *Link) Album() (*Album, error) {
	if l.Type() != LinkTypeAlbum {
		return nil, errors.New("spotify: link is not an album")
	}
	return newAlbum(l.session, C.sp_link_as_album(l.sp_link)), nil
}

func (l *Link) Artist() (*Artist, error) {
	if l.Type() != LinkTypeArtist {
		return nil, errors.New("spotify: link is not an artist")
	}
	return newArtist(l.session, C.sp_link_as_artist(l.sp_link)), nil
}

func (l *Link) Playlist() (*Playlist, error) {
	if l.Type() != LinkTypePlaylist {
		return nil, errors.New("spotify: link is not a playlist")
	}

	sp_playlist := C.sp_playlist_create(l.session.sp_session, l.sp_link)
	return newPlaylist(l.session, sp_playlist, true), nil
}

func (l *Link) User() (*User, error) {
	if l.Type() != LinkTypeUser {
		return nil, errors.New("spotify: link is not for a user")
	}
	return newUser(l.session, C.sp_link_as_user(l.sp_link)), nil
}

type Search struct {
	session   *Session
	sp_search *C.sp_search
	wg        sync.WaitGroup
}

func newSearch(session *Session, query string, opts *SearchOptions) (*Search, error) {
	s := &Search{session: session}
	s.wg.Add(1)

	cquery := C.CString(query)
	defer C.free(unsafe.Pointer(cquery))

	s.sp_search = C.search_create(
		s.session.sp_session,
		cquery,
		C.int(opts.Tracks.Offset),
		C.int(opts.Tracks.Count),
		C.int(opts.Albums.Offset),
		C.int(opts.Albums.Count),
		C.int(opts.Artists.Offset),
		C.int(opts.Artists.Count),
		C.int(opts.Playlists.Offset),
		C.int(opts.Playlists.Count),
		C.sp_search_type(opts.Type),
		unsafe.Pointer(s),
	)
	if s.sp_search == nil {
		return nil, errors.New("spotify: failed to search")
	}
	runtime.SetFinalizer(s, (*Search).release)
	return s, nil
}

func (s *Search) release() {
	if s.sp_search == nil {
		panic("spotify: search object has no sp_search object")
	}
	C.sp_search_release(s.sp_search)
	s.sp_search = nil
}

func (s *Search) Wait() {
	s.wg.Wait()
}

func (s *Search) Link() *Link {
	sp_link := C.sp_link_create_from_search(s.sp_search)
	return newLink(s.session, sp_link, false)
}

func (s *Search) cbComplete() {
	s.wg.Done()
}

func (s *Search) Error() error {
	return spError(C.sp_search_error(s.sp_search))
}

func (s *Search) Query() string {
	return C.GoString(C.sp_search_query(s.sp_search))
}

func (s *Search) DidYouMean() string {
	return C.GoString(C.sp_search_did_you_mean(s.sp_search))
}

func (s *Search) Tracks() int {
	return int(C.sp_search_num_tracks(s.sp_search))
}

func (s *Search) TotalTracks() int {
	return int(C.sp_search_total_tracks(s.sp_search))
}

func (s *Search) Track(n int) *Track {
	if n < 0 || n >= s.Tracks() {
		panic("spotify: search track out of range")
	}
	sp_track := C.sp_search_track(s.sp_search, C.int(n))
	return newTrack(s.session, sp_track)
}

func (s *Search) Albums() int {
	return int(C.sp_search_num_albums(s.sp_search))
}

func (s *Search) TotalAlbums() int {
	return int(C.sp_search_total_albums(s.sp_search))
}

func (s *Search) Album(n int) *Album {
	if n < 0 || n >= s.Albums() {
		panic("spotify: search album out of range")
	}
	sp_album := C.sp_search_album(s.sp_search, C.int(n))
	return newAlbum(s.session, sp_album)
}

func (s *Search) Artists() int {
	return int(C.sp_search_num_artists(s.sp_search))
}

func (s *Search) TotalArtists() int {
	return int(C.sp_search_total_artists(s.sp_search))
}

func (s *Search) Artist(n int) *Artist {
	if n < 0 || n >= s.Artists() {
		panic("spotify: search artist out of range")
	}
	sp_artist := C.sp_search_artist(s.sp_search, C.int(n))
	return newArtist(s.session, sp_artist)
}

func (s *Search) Playlists() int {
	return int(C.sp_search_num_playlists(s.sp_search))
}

func (s *Search) TotalPlaylists() int {
	return int(C.sp_search_total_playlists(s.sp_search))
}

// TODO sp_search_playlist

type Track struct {
	session  *Session
	sp_track *C.sp_track
	wg       sync.WaitGroup
}

func newTrack(s *Session, t *C.sp_track) *Track {
	C.sp_track_add_ref(t)
	track := &Track{session: s, sp_track: t}
	runtime.SetFinalizer(track, (*Track).release)

	if s.listenForMetadataUpdates(track.isLoaded, track) {
		track.wg.Add(1)
	}
	return track
}

func (t *Track) release() {
	if t.sp_track == nil {
		panic("spotify: track object has no sp_track object")
	}
	C.sp_track_release(t.sp_track)
	t.sp_track = nil
}

func (t *Track) cbUpdated() {
	if t.isLoaded() {
		t.wg.Done()
	}
}

func (t *Track) Wait() {
	t.wg.Wait()
	if !t.isLoaded() {
		panic("spotify: track is not loaded")
	}
	t.session.stopListenForMetadataUpdates(t)
}

func (t *Track) isLoaded() bool {
	return C.sp_track_is_loaded(t.sp_track) == 1
}

// Error returns an error associated with a track.
func (t *Track) Error() error {
	return spError(C.sp_track_error(t.sp_track))
}

func (t *Track) OfflineStatus() TrackOfflineStatus {
	status := C.sp_track_offline_get_status(t.sp_track)
	return TrackOfflineStatus(status)
}

// Availability returns the track availability.
func (t *Track) Availability() TrackAvailability {
	avail := C.sp_track_get_availability(
		t.session.sp_session,
		t.sp_track,
	)
	return TrackAvailability(avail)
}

// IsLocal returns true if the track is a local file.
func (t *Track) IsLocal() bool {
	local := C.sp_track_is_local(
		t.session.sp_session,
		t.sp_track,
	)
	return local == 1
}

// IsAutoLinked returns true if the track is auto-linked to another track.
func (t *Track) IsAutoLinked() bool {
	linked := C.sp_track_is_autolinked(
		t.session.sp_session,
		t.sp_track,
	)
	return linked == 1
}

// PlayableTrack returns the track which is the actual track that will be
// played if the given track is played.
func (t *Track) PlayableTrack() *Track {
	sp_track := C.sp_track_get_playable(
		t.session.sp_session,
		t.sp_track,
	)
	return newTrack(t.session, sp_track)
}

// IsPlaceholder returns true if the track is a placeholder. Placeholder tracks
// are used to store other objects than tracks in the playlist. Currently this
// is used in the inbox to store artists, albums and playlists.
//
// Use Link() to get a link object that points to the real object this "track"
// points to.
func (t *Track) IsPlaceholder() bool {
	placeholder := C.sp_track_is_placeholder(
		t.sp_track,
	)
	return placeholder == 1
}

// Link returns a link object representing the track.
func (t *Track) Link() *Link {
	return t.LinkOffset(0)
}

// Link returns a link object representing the track at the given offset.
func (t *Track) LinkOffset(offset time.Duration) *Link {
	offsetMs := C.int(offset / time.Millisecond)
	sp_link := C.sp_link_create_from_track(t.sp_track, offsetMs)
	return newLink(t.session, sp_link, false)
}

// IsStarred returns true if the track is starred by the currently logged in
// user.
func (t *Track) IsStarred() bool {
	starred := C.sp_track_is_starred(
		t.session.sp_session,
		t.sp_track,
	)
	return starred == 1
}

// TODO sp_track_set_starred

// Artists returns the number of artists performing on the track.
func (t *Track) Artists() int {
	return int(C.sp_track_num_artists(t.sp_track))
}

// Artist returns the artist on the specified index. Use Artists to know how
// many artists that performed on the track.
func (t *Track) Artist(n int) *Artist {
	if n < 0 || n >= t.Artists() {
		panic("spotify: track artist index out of range")
	}
	sp_artist := C.sp_track_artist(t.sp_track, C.int(n))
	return newArtist(t.session, sp_artist)
}

// Album returns the album of the track.
func (t *Track) Album() *Album {
	sp_album := C.sp_track_album(t.sp_track)
	return newAlbum(t.session, sp_album)
}

// Name returns the track name.
func (t *Track) Name() string {
	return C.GoString(C.sp_track_name(t.sp_track))
}

// Duration returns the length of the current track.
func (t *Track) Duration() time.Duration {
	ms := C.sp_track_duration(t.sp_track)
	return time.Duration(ms) * time.Millisecond
}

// Popularity is in the range [0, 100].
type Popularity int

// Popularity returns the popularity for the track.
func (t *Track) Popularity() Popularity {
	p := C.sp_track_popularity(t.sp_track)
	return Popularity(p)
}

// Disc returns the disc number for the track.
func (t *Track) Disc() int {
	return int(C.sp_track_disc(t.sp_track))
}

// Position returns the position of a track on its disc.
// It starts at 1 (relative the corresponding disc).
//
// This function returns valid data only for tracks
// appearing in a browse artist or browse album result
// (otherwise returns 0).
func (t *Track) Index() int {
	return int(C.sp_track_index(t.sp_track))
}

// TODO sp_localtrack_create

type TrackAvailability C.sp_track_availability

const (
	// Track is not available
	TrackAvailabilityUnavailable = TrackAvailability(C.SP_TRACK_AVAILABILITY_UNAVAILABLE)

	// Track is available and can be played
	TrackAvailabilityAvailable = TrackAvailability(C.SP_TRACK_AVAILABILITY_AVAILABLE)

	// Track can not be streamed using this account
	TrackAvailabilityNotStreamable = TrackAvailability(C.SP_TRACK_AVAILABILITY_NOT_STREAMABLE)

	// Track not available on artist's request
	TrackAvailabilityBannedByArtist = TrackAvailability(C.SP_TRACK_AVAILABILITY_BANNED_BY_ARTIST)
)

type TrackOfflineStatus C.sp_track_offline_status

const (
	// Not marked for offline
	TrackOfflineNo = TrackOfflineStatus(C.SP_TRACK_OFFLINE_NO)
	// Waiting for download
	TrackOfflineWaiting = TrackOfflineStatus(C.SP_TRACK_OFFLINE_WAITING)
	// Currently downloading
	TrackOfflineDownloading = TrackOfflineStatus(C.SP_TRACK_OFFLINE_DOWNLOADING)
	// Downloaded OK and can be played
	TrackOfflineDone = TrackOfflineStatus(C.SP_TRACK_OFFLINE_DONE)
	// TrackOfflineStatus during download
	TrackOfflineTrackOfflineStatus = TrackOfflineStatus(C.SP_TRACK_OFFLINE_ERROR)
	// Downloaded OK but not playable due to expiery
	TrackOfflineDoneExpired = TrackOfflineStatus(C.SP_TRACK_OFFLINE_DONE_EXPIRED)
	// Waiting because device have reached max number of allowed tracks
	TrackOfflineLimitExceeded = TrackOfflineStatus(C.SP_TRACK_OFFLINE_LIMIT_EXCEEDED)
	// Downloaded OK and available but scheduled for re-download
	TrackOfflineDoneResync = TrackOfflineStatus(C.SP_TRACK_OFFLINE_DONE_RESYNC)
)

type Album struct {
	session  *Session
	sp_album *C.sp_album
	wg       sync.WaitGroup
}

type AlbumType C.sp_albumtype

const (
	// Normal album
	AlbumTypeAlbum = AlbumType(C.SP_ALBUMTYPE_ALBUM)
	// Single
	AlbumTypeSingle = AlbumType(C.SP_ALBUMTYPE_SINGLE)
	// Compilation
	AlbumTypeCompilation = AlbumType(C.SP_ALBUMTYPE_COMPILATION)
	// Unknown type
	AlbumTypeUnknown = AlbumType(C.SP_ALBUMTYPE_UNKNOWN)
)

func newAlbum(s *Session, sp_album *C.sp_album) *Album {
	C.sp_album_add_ref(sp_album)
	album := &Album{session: s, sp_album: sp_album}
	runtime.SetFinalizer(album, (*Album).release)

	if s.listenForMetadataUpdates(album.isLoaded, album) {
		album.wg.Add(1)
	}
	return album
}

func (a *Album) release() {
	if a.sp_album == nil {
		panic("spotify: album object has no sp_album object")
	}
	C.sp_album_release(a.sp_album)
	a.sp_album = nil
}

func (a *Album) cbUpdated() {
	if a.isLoaded() {
		a.wg.Done()
	}
}

func (a *Album) Wait() {
	a.wg.Wait()
	if !a.isLoaded() {
		panic("spotify: album is not loaded")
	}
	a.session.stopListenForMetadataUpdates(a)
}

// Link creates a link object from the album.
func (a *Album) Link() *Link {
	sp_link := C.sp_link_create_from_album(a.sp_album)
	return newLink(a.session, sp_link, false)
}

// IsAvailable returns true if the album is available in the current region and
// for playback.
func (a *Album) IsAvailable() bool {
	return C.sp_album_is_available(a.sp_album) == 1
}

func (a *Album) Artist() *Artist {
	// TODO we never should wait for metadata updates?
	return newArtist(a.session, C.sp_album_artist(a.sp_album))
}

// TODO sp_album_cover
// TODO sp_link_create_from_album_cover

// Name returns the name of the album.
func (a *Album) Name() string {
	return C.GoString(C.sp_album_name(a.sp_album))
}

// Year returns the release year.
func (a *Album) Year() int {
	return int(C.sp_album_year(a.sp_album))
}

// Type returns the type of album.
func (a *Album) Type() AlbumType {
	return AlbumType(C.sp_album_type(a.sp_album))
}

func (a *Album) isLoaded() bool {
	return C.sp_album_is_loaded(a.sp_album) == 1
}

type Artist struct {
	session   *Session
	sp_artist *C.sp_artist
	wg        sync.WaitGroup
}

func newArtist(s *Session, sp_artist *C.sp_artist) *Artist {
	C.sp_artist_add_ref(sp_artist)
	artist := &Artist{session: s, sp_artist: sp_artist}
	runtime.SetFinalizer(artist, (*Artist).release)

	if s.listenForMetadataUpdates(artist.isLoaded, artist) {
		artist.wg.Add(1)
	}
	return artist
}

func (a *Artist) release() {
	if a.sp_artist == nil {
		panic("spotify: artist object has no sp_artist object")
	}
	C.sp_artist_release(a.sp_artist)
	a.sp_artist = nil
}

func (a *Artist) cbUpdated() {
	if a.isLoaded() {
		a.wg.Done()
	}
}

func (a *Artist) isLoaded() bool {
	return C.sp_artist_is_loaded(a.sp_artist) == 1
}

func (a *Artist) Wait() {
	a.wg.Wait()
	if !a.isLoaded() {
		panic("spotify: artist is not loaded")
	}
	a.session.stopListenForMetadataUpdates(a)
}

// Link creates a link object from the artist.
func (a *Artist) Link() *Link {
	sp_link := C.sp_link_create_from_artist(a.sp_artist)
	return newLink(a.session, sp_link, false)
}

// Name returns the name of the artist.
func (a *Artist) Name() string {
	return C.GoString(C.sp_artist_name(a.sp_artist))
}

// TODO sp_artist_portrait
// TODO sp_link_create_from_artist_portrait

type RelationType C.sp_relation_type

const (
	// Not yet known
	RelationTypeUnknown = RelationType(C.SP_RELATION_TYPE_UNKNOWN)
	// No relation
	RelationTypeNone = RelationType(C.SP_RELATION_TYPE_NONE)
	// The currently logged in user is following this uer
	RelationTypeUnIdirectional = RelationType(C.SP_RELATION_TYPE_UNIDIRECTIONAL)
	// Bidirectional friendship established
	RelationTypeBidirectional = RelationType(C.SP_RELATION_TYPE_BIDIRECTIONAL)
)

type User struct {
	session *Session
	sp_user *C.sp_user

	wg sync.WaitGroup
}

func newUser(s *Session, sp_user *C.sp_user) *User {
	C.sp_user_add_ref(sp_user)
	user := &User{session: s, sp_user: sp_user}
	// TODO make an inteface with release and some convenient func
	runtime.SetFinalizer(user, (*User).release)

	if s.listenForUserInfoUpdates(user.isLoaded, user) {
		user.wg.Add(1)
	}

	return user
}

func (u *User) release() {
	if u.sp_user == nil {
		panic("spotify: user object has no sp_user object")
	}
	C.sp_user_release(u.sp_user)
	u.sp_user = nil
}

func (u *User) cbUpdated() {
	if u.isLoaded() {
		u.wg.Done()
	}
}

func (u *User) Wait() {
	u.wg.Wait()
	u.session.stopListenForUserInfoUpdates(u)
}

func (u *User) isLoaded() bool {
	return C.sp_user_is_loaded(u.sp_user) == 1
}

// CanonicalName returns the user's canonical username.
func (u *User) CanonicalName() string {
	return C.GoString(C.sp_user_canonical_name(u.sp_user))
}

// ArtistsToplist loads the artist toplist for the user.
func (u *User) ArtistsToplist() *ArtistsToplist {
	return newArtistsToplist(u.session, toplistRegionUser, u)
}

// AlbumsToplist loads the album toplist for the user.
func (u *User) AlbumsToplist() *AlbumsToplist {
	return newAlbumsToplist(u.session, toplistRegionUser, u)
}

// TracksToplist loads the track toplist for the user.
func (u *User) TracksToplist() *TracksToplist {
	return newTracksToplist(u.session, toplistRegionUser, u)
}

// DisplayName returns the user's displayable username.
func (u *User) DisplayName() string {
	return C.GoString(C.sp_user_display_name(u.sp_user))
}

func (u *User) Starred() *Playlist {
	cuser := C.CString(u.CanonicalName())
	defer C.free(unsafe.Pointer(cuser))
	sp_playlist := C.sp_session_starred_for_user_create(u.session.sp_session, cuser)
	return newPlaylist(u.session, sp_playlist, true)
}

type Playlist struct {
	session     *Session
	sp_playlist *C.sp_playlist
	callbacks   C.sp_playlist_callbacks
	refOwned    bool

	mu     sync.Mutex
	wg     sync.WaitGroup
	loaded chan struct{}
}

func newPlaylist(s *Session, sp_playlist *C.sp_playlist, refOwned bool) *Playlist {
	// TODO register all callbacks
	p := &Playlist{
		session:     s,
		sp_playlist: sp_playlist,
		refOwned:    refOwned,
		loaded:      make(chan struct{}, 1),
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	runtime.SetFinalizer(p, (*Playlist).release)
	C.set_playlist_callbacks(&p.callbacks)
	C.sp_playlist_add_callbacks(sp_playlist, &p.callbacks, unsafe.Pointer(p))

	// TODO make a nice interface and expose channel
	if p.isLoaded() {
		p.loaded <- struct{}{}
	} else {
		p.wg.Add(1)
	}

	return p
}

func (p *Playlist) release() {
	if p.sp_playlist == nil {
		panic("spotify: playlist object has no sp_playlist object")
	}
	C.sp_playlist_remove_callbacks(p.sp_playlist, &p.callbacks, unsafe.Pointer(p))
	if p.refOwned {
		C.sp_playlist_release(p.sp_playlist)
	}
	p.sp_playlist = nil
}

func (p *Playlist) isLoaded() bool {
	return C.sp_playlist_is_loaded(p.sp_playlist) == 1
}

func (p *Playlist) cbStateChanged() {
	if p.isLoaded() {
		select {
		case p.loaded <- struct{}{}:
			p.wg.Done()
		}
	}
}

//export go_playlist_state_changed
func go_playlist_state_changed(sp_playlist unsafe.Pointer, userdata unsafe.Pointer) {
	(*Playlist)(userdata).cbStateChanged()
}

func (p *Playlist) Wait() {
	p.wg.Wait()
}

func (p *Playlist) Link() *Link {
	sp_link := C.sp_link_create_from_playlist(p.sp_playlist)
	return newLink(p.session, sp_link, false)
}

func (p *Playlist) Name() string {
	return C.GoString(C.sp_playlist_name(p.sp_playlist))
}

func (p *Playlist) SetName(n string) error {
	cname := C.CString(n)
	defer C.free(unsafe.Pointer(cname))
	rc := C.sp_playlist_rename(p.sp_playlist, cname)
	if rc != C.SP_ERROR_OK {
		return spError(rc)
	}
	return nil
}

func (p *Playlist) Owner() (*User, error) {
	sp_user := C.sp_playlist_owner(p.sp_playlist)
	if sp_user == nil {
		return nil, errors.New("spotify: unknown user")
	}
	return newUser(p.session, sp_user), nil
}

func (p *Playlist) Tracks() int {
	return int(C.sp_playlist_num_tracks(p.sp_playlist))
}

func (p *Playlist) Track(n int) *PlaylistTrack {
	if n < 0 || n >= p.Tracks() {
		panic("spotify: playlist track out of range")
	}
	// TODO hook into the playlist to know when the index changes etc?
	return &PlaylistTrack{p, n}
}

func (p *Playlist) Collaborative() bool {
	return C.sp_playlist_is_collaborative(p.sp_playlist) == 1
}

func (p *Playlist) SetCollaborative(c bool) {
	C.sp_playlist_set_collaborative(p.sp_playlist, cbool(c))
}

// SetAutolinkTracks sets the autolinking state for a playlist.
//
// If a playlist is autolinked, unplayable tracks will be made playable by
// linking them to other Spotify tracks, where possible.
func (p *Playlist) SetAutolinkTracks(l bool) {
	C.sp_playlist_set_autolink_tracks(p.sp_playlist, cbool(l))
}

func (p *Playlist) Description() string {
	return C.GoString(C.sp_playlist_get_description(p.sp_playlist))
}

// TODO sp_playlist_get_image

func (p *Playlist) HasPendingChanges() bool {
	return C.sp_playlist_has_pending_changes(p.sp_playlist) == 1
}

// TODO sp_playlist_add_tracks
// TODO sp_playlist_remove_tracks
// TODO sp_playlist_reorder_tracks

func (p *Playlist) NumSubscribers() int {
	return int(C.sp_playlist_num_subscribers(p.sp_playlist))
}

// TODO sp_playlist_subscribers

func (p *Playlist) InMemory() bool {
	return C.sp_playlist_is_in_ram(p.session.sp_session, p.sp_playlist) == 1
}

func (p *Playlist) LoadInMemory(m bool) {
	C.sp_playlist_set_in_ram(p.session.sp_session, p.sp_playlist, cbool(m))
}

func (p *Playlist) SetOffline(o bool) {
	C.sp_playlist_set_offline_mode(p.session.sp_session, p.sp_playlist, cbool(o))
}

func (p *Playlist) Offline() PlaylistOfflineStatus {
	s := C.sp_playlist_get_offline_status(p.session.sp_session, p.sp_playlist)
	return PlaylistOfflineStatus(s)
}

type PlaylistOfflineStatus C.sp_playlist_offline_status

const (
	// Playlist is not offline enabled
	PlaylistOfflineStatusNo = PlaylistOfflineStatus(C.SP_PLAYLIST_OFFLINE_STATUS_NO)
	// Playlist is synchronized to local storage
	PlaylistOfflineStatusYes = PlaylistOfflineStatus(C.SP_PLAYLIST_OFFLINE_STATUS_YES)
	// This playlist is currently downloading. Only one playlist can be in this state any given time
	PlaylistOfflineStatusDownloading = PlaylistOfflineStatus(C.SP_PLAYLIST_OFFLINE_STATUS_DOWNLOADING)
	// Playlist is queued for download
	PlaylistOfflineStatusWaiting = PlaylistOfflineStatus(C.SP_PLAYLIST_OFFLINE_STATUS_WAITING)
)

type PlaylistTrack struct {
	playlist *Playlist
	index    int
}

// User returns the user that added the track to the playlist.
func (pt *PlaylistTrack) User() *User {
	sp_user := C.sp_playlist_track_creator(pt.playlist.sp_playlist, C.int(pt.index))
	return newUser(pt.playlist.session, sp_user)
}

// Time returns the time when the track was added to the playlist.
func (pt *PlaylistTrack) Time() time.Time {
	t := C.sp_playlist_track_create_time(pt.playlist.sp_playlist, C.int(pt.index))
	return time.Unix(int64(t), 0)
}

// Track returns the track metadata object for the playlist entry.
func (pt *PlaylistTrack) Track() *Track {
	// TODO return PlaylistTrack and add extra functionality on top of that
	sp_track := C.sp_playlist_track(pt.playlist.sp_playlist, C.int(pt.index))
	return newTrack(pt.playlist.session, sp_track)
}

// Seen returns true if the entry has been marked as seen or not.
func (pt *PlaylistTrack) Seen() bool {
	seen := C.sp_playlist_track_seen(pt.playlist.sp_playlist, C.int(pt.index))
	return seen == 1
}

// SetSeen marks the playlist track item as seen or not.
func (pt *PlaylistTrack) SetSeen(seen bool) error {
	rc := C.sp_playlist_track_set_seen(pt.playlist.sp_playlist, C.int(pt.index), cbool(seen))
	if rc != C.SP_ERROR_OK {
		return spError(rc)
	}
	return nil
}

// Message returns the message attached to a playlist item. Typically used on inbox.
// TODO only expose this for inbox?
func (pt *PlaylistTrack) Message() string {
	cmsg := C.sp_playlist_track_message(pt.playlist.sp_playlist, C.int(pt.index))
	if cmsg == nil {
		return ""
	}
	return C.GoString(cmsg)
}

type toplistType C.sp_toplisttype

const (
	toplistTypeArtists = toplistType(C.SP_TOPLIST_TYPE_ARTISTS)
	toplistTypeAlbums  = toplistType(C.SP_TOPLIST_TYPE_ALBUMS)
	toplistTypeTracks  = toplistType(C.SP_TOPLIST_TYPE_TRACKS)
)

type Region int

func (r Region) String() string {
	return string([]byte{byte(r >> 8), byte(r)})
}

type ToplistRegion Region

const (
	// Global toplist
	ToplistRegionEverywhere = ToplistRegion(C.SP_TOPLIST_REGION_EVERYWHERE)

	// Toplist for the given user
	toplistRegionUser = ToplistRegion(C.SP_TOPLIST_REGION_USER)
)

// NewToplistRegion returns the toplist region for a ISO
// 3166-1 country code.
//
// Also see ToplistRegionEverywhere and ToplistRegionUser
// for some special constants.
func NewToplistRegion(region string) (ToplistRegion, error) {
	if len(region) != 2 {
		return 0, errors.New("spotify: invalid toplist region")
	}
	region = strings.ToUpper(region)
	r := int(region[0])<<8 | int(region[1])
	return ToplistRegion(r), nil
}

func (r ToplistRegion) String() string {
	switch r {
	case ToplistRegionEverywhere:
		return "Worldwide"
	case toplistRegionUser:
		return "User"
	default:
		return (Region)(r).String()
	}
}

type toplist struct {
	session *Session

	sp_toplistbrowse *C.sp_toplistbrowse
	ttype            toplistType

	wg sync.WaitGroup
}

// newToplist creates a wrapper around the toplist object. If the user object
// is nil, the global toplist for the region will be used. Both user and region
// can be specified if the toplist for the user's region should be fetched.
func newToplist(s *Session, ttype toplistType, r ToplistRegion, user *User) *toplist {
	var cusername *C.char
	if user != nil {
		cusername = C.CString(user.CanonicalName())
		defer C.free(unsafe.Pointer(cusername))
	}

	t := &toplist{session: s, ttype: ttype}
	t.wg.Add(1)
	t.sp_toplistbrowse = C.toplistbrowse_create(
		t.session.sp_session,
		C.sp_toplisttype(ttype),
		C.sp_toplistregion(r),
		cusername,
		unsafe.Pointer(&t),
	)
	runtime.SetFinalizer(t, (*toplist).release)
	return t
}

func (t *toplist) release() {
	if t.sp_toplistbrowse == nil {
		panic("spotify: toplist object has no sp_toplistbrowse object")
	}
	C.sp_toplistbrowse_release(t.sp_toplistbrowse)
	t.sp_toplistbrowse = nil
}

func (t *toplist) cbComplete() {
	println("toplist done", t)
	t.wg.Done()
}

func (t *toplist) Wait() {
	println("waiting for toplist", t)
	t.wg.Wait()
}

func (t *toplist) Error() error {
	return spError(C.sp_toplistbrowse_error(t.sp_toplistbrowse))
}

// Duration returns the time spent waiting for
// the Spotify backend to serve the toplist.
func (t *toplist) Duration() time.Duration {
	ms := C.sp_toplistbrowse_backend_request_duration(t.sp_toplistbrowse)
	if ms < 0 {
		ms = 0
	}
	return time.Duration(ms) * time.Millisecond
}

// TODO plural here, really?
type ArtistsToplist struct {
	*toplist
}

func newArtistsToplist(s *Session, r ToplistRegion, user *User) *ArtistsToplist {
	toplist := newToplist(s, toplistTypeArtists, r, user)
	return &ArtistsToplist{toplist}
}

func (at *ArtistsToplist) Artists() int {
	return int(C.sp_toplistbrowse_num_artists(at.sp_toplistbrowse))
}

func (at *ArtistsToplist) Artist(n int) *Artist {
	if n < 0 || n >= at.Artists() {
		panic("spotify: toplist artist out of range")
	}
	sp_artist := C.sp_toplistbrowse_artist(at.sp_toplistbrowse, C.int(n))
	return newArtist(at.session, sp_artist)
}

// TODO
type AlbumsToplist struct {
	*toplist
}

func newAlbumsToplist(s *Session, r ToplistRegion, user *User) *AlbumsToplist {
	toplist := newToplist(s, toplistTypeAlbums, r, user)
	return &AlbumsToplist{toplist}
}

func (at *AlbumsToplist) Albums() int {
	return int(C.sp_toplistbrowse_num_albums(at.sp_toplistbrowse))
}

func (at *AlbumsToplist) Album(n int) *Album {
	if n < 0 || n >= at.Albums() {
		panic("spotify: toplist album out of range")
	}
	sp_album := C.sp_toplistbrowse_album(at.sp_toplistbrowse, C.int(n))
	return newAlbum(at.session, sp_album)
}

type TracksToplist struct {
	*toplist
}

func newTracksToplist(s *Session, r ToplistRegion, user *User) *TracksToplist {
	toplist := newToplist(s, toplistTypeTracks, r, user)
	return &TracksToplist{toplist}
}

// Tracks returns the numbers of tracks in the toplist.
func (tt *TracksToplist) Tracks() int {
	return int(C.sp_toplistbrowse_num_tracks(tt.sp_toplistbrowse))
}

// Track returns the track given the index from the toplist.
func (tt *TracksToplist) Track(n int) *Track {
	if n < 0 || n >= tt.Tracks() {
		panic("spotify: toplist track out of range")
	}
	sp_track := C.sp_toplistbrowse_track(tt.sp_toplistbrowse, C.int(n))
	return newTrack(tt.session, sp_track)
}

// BuildId returns the libspotify build ID.
func BuildId() string {
	return C.GoString(C.sp_build_id())
}
