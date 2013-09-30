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

// Package libspotify adds language bindings for libspotify in Go. The
// libspotify C API package allows third-party developers to write applications
// that utilize the Spotify music streaming service.
package libspotify

/*
#cgo pkg-config: libspotify
#include <libspotify/api.h>
#include "libspotify.h"
*/
import "C"

import (
	"errors"
	"runtime"
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

	CacheLocation    string
	SettingsLocation string
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

const (
	eWakeup event = iota
	eStop
)

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
	config  C.sp_session_config
	session *C.sp_session
	mu      sync.Mutex

	events chan event

	credentialsBlobs chan []byte
	states           chan struct{}
	loggedIn         chan error
	loggedOut        chan struct{}

	wg      sync.WaitGroup
	dealloc sync.Once
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
		events: make(chan event, 1),

		credentialsBlobs: make(chan []byte, 1),
		states:           make(chan struct{}, 1),
		loggedIn:         make(chan error, 1),
		loggedOut:        make(chan struct{}, 1),
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

		err := spError(C.sp_session_create(&session.config, &session.session))
		errc <- err
		if err != nil {
			return
		}
		session.processEvents()
	}()

	if err := <-errc; err != nil {
		return nil, err
	}

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
		err = spError(C.sp_session_release(s.session))

		s.events <- eStop
		s.wg.Wait()

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
		s.session,
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
	return spError(C.sp_session_relogin(s.session))
}

// Logout logs the currently logged in user out
//
// Always call this before terminating the application and
// libspotify is currently logged in. Otherwise, the settings and
// cache may be lost.
func (s *Session) Logout() error {
	return spError(C.sp_session_logout(s.session))
}

// FlushCaches makes libspotify write all data that is meant to
// be stored on disk to the disk immediately. libspotify does this
// periodically by itself and also on logout. Under normal
// conditions this shouldn't be needed.
func (s *Session) FlushCaches() error {
	return spError(C.sp_session_flush_caches(s.session))
}

// ConnectionState returns the current connection state for the
// session.
func (s *Session) ConnectionState() ConnectionState {
	state := C.sp_session_connectionstate(s.session)
	return ConnectionState(state)
}

// CredentialsBlobUpdates returns a channel used to get updates
// for credential blobs.
func (s *Session) CredentialsBlobUpdates() <-chan []byte {
	return s.credentialsBlobs
}

// ConnectionStateUpdates returns a channel used to get updates on
// the connection state.
func (s *Session) ConnectionStateUpdates() <-chan struct{} {
	return s.states
}

// LoginUpdates returns a channel used to get notified when the
// session has been logged in.
func (s *Session) LoginUpdates() <-chan error {
	return s.loggedIn
}

// LogoutUpdates returns a channel used to get notified when the
// session has been logged out.
func (s *Session) LogoutUpdates() <-chan struct{} {
	return s.loggedOut
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
	// Track is the number of tracks to search for
	Track SearchSpec

	// Album is the number of albums to search for
	Album SearchSpec

	// Artist is the number of artists to search for
	Artist SearchSpec

	// Playlist is the number of playlists to search for
	Playlist SearchSpec

	// Type is the search type. Defaults to normal searching.
	Type SearchType
}

// Search searches Spotify for track, album, artist and / or playlists.
func (s *Session) Search(query string, opts *SearchOptions) *search {
	cquery := C.CString(query)
	defer C.free(unsafe.Pointer(cquery))

	s.mu.Lock()
	defer s.mu.Unlock()

	var search search
	sp_search := C.search_create(
		s.session,
		cquery,
		C.int(opts.Track.Offset),
		C.int(opts.Track.Count),
		C.int(opts.Album.Offset),
		C.int(opts.Album.Count),
		C.int(opts.Artist.Offset),
		C.int(opts.Artist.Count),
		C.int(opts.Playlist.Offset),
		C.int(opts.Playlist.Count),
		C.sp_search_type(opts.Type),
		unsafe.Pointer(&search),
	)
	search.init(s, sp_search)
	return &search
}

func (s *Session) processEvents() {
	var nextTimeoutMs C.int

	s.wg.Add(1)
	defer s.wg.Done()

	for {
		s.mu.Lock()
		rc := C.sp_session_process_events(s.session, &nextTimeoutMs)
		s.mu.Unlock()
		if err := spError(rc); err != nil {
			println("process error err", err)
			continue
		}

		timeout := time.Duration(nextTimeoutMs) * time.Millisecond
		select {
		case <-time.After(timeout):
		case evt := <-s.events:
			if evt == eStop {
				return
			}
		}
	}
}

func (s *Session) cbLoggedIn(err error) {
	println("logged in called", s, err)
	select {
	case s.loggedIn <- err:
	default:
		println("failed to send logged in event")
	}
}

func (s *Session) cbLoggedOut() {
	println("logged out called", s)
	select {
	case s.loggedOut <- struct{}{}:
	default:
		println("failed to send logged out event")
	}
}

func (s *Session) cbConnectionError(err error) {
	println("connection errror called", s, err)
}

func (s *Session) cbNotifyMainThread() {
	select {
	case s.events <- eWakeup:
	default:
		println("failed to notify main thread")
		// TODO generate (internal) log message
	}
}

func (s *Session) cbLogMessage(message string) {
	println("LOG", message)
}

func (s *Session) cbCredentialsBlobUpdated(blob []byte) {
	select {
	case s.credentialsBlobs <- blob:
	default:
	}
}

func (s *Session) cbConnectionStateUpdated() {
	select {
	case s.states <- struct{}{}:
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

//export go_connection_error
func go_connection_error(spSession unsafe.Pointer, spErr C.sp_error) {
	sessionCall(spSession, func(s *Session) {
		s.cbConnectionError(spError(spErr))
	})
}

//export go_notify_main_thread
func go_notify_main_thread(spSession unsafe.Pointer) {
	sessionCall(spSession, (*Session).cbNotifyMainThread)
}

//export go_log_message
func go_log_message(spSession unsafe.Pointer, data *C.char) {
	sessionCall(spSession, func(s *Session) {
		message := C.GoString(data)
		s.cbLogMessage(message)
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

//export go_search_complete
func go_search_complete(spSearch unsafe.Pointer, userdata unsafe.Pointer) {
	s := (*search)(userdata)
	s.cbComplete()
}

type search struct {
	session   *Session
	sp_search *C.sp_search
	wg        sync.WaitGroup
}

func (s *search) init(session *Session, sp_search *C.sp_search) {
	s.session = session
	s.sp_search = sp_search
	s.wg.Add(1)
	runtime.SetFinalizer(s, (*search).finalize)
}

func (s *search) finalize() {
	if s.sp_search != nil {
		C.sp_search_release(s.sp_search)
		s.sp_search = nil
	}
}

func (s *search) Wait() error {
	s.wg.Wait()
	return s.Error()
}

func (s *search) cbComplete() {
	s.wg.Done()
}

func (s *search) Error() error {
	return spError(C.sp_search_error(s.sp_search))
}

func (s *search) Query() string {
	return C.GoString(C.sp_search_query(s.sp_search))
}

func (s *search) DidYouMean() string {
	return C.GoString(C.sp_search_did_you_mean(s.sp_search))
}

func (s *search) Tracks() int {
	return int(C.sp_search_num_tracks(s.sp_search))
}

func (s *search) TotalTracks() int {
	return int(C.sp_search_total_tracks(s.sp_search))
}

func (s *search) Track(n int) *Track {
	if n < 0 || n >= s.Tracks() {
		panic("spotify: search track out of range")
	}
	sp_track := C.sp_search_track(s.sp_search, C.int(n))
	return newTrack(s.session, sp_track)
}

func (s *search) Albums() int {
	return int(C.sp_search_num_albums(s.sp_search))
}

func (s *search) TotalAlbums() int {
	return int(C.sp_search_total_albums(s.sp_search))
}

func (s *search) Artists() int {
	return int(C.sp_search_num_artists(s.sp_search))
}

func (s *search) TotalArtists() int {
	return int(C.sp_search_total_artists(s.sp_search))
}

func (s *search) Playlists() int {
	return int(C.sp_search_num_playlists(s.sp_search))
}

func (s *search) TotalPlaylists() int {
	return int(C.sp_search_total_playlists(s.sp_search))
}

type Track struct {
	session  *Session
	sp_track *C.sp_track
	wg       sync.WaitGroup
}

func newTrack(s *Session, t *C.sp_track) *Track {
	C.sp_track_add_ref(t)
	track := &Track{
		session:  s,
		sp_track: t,
	}
	runtime.SetFinalizer(track, (*Track).finalize)
	return track
}

func (t *Track) finalize() {
	if t.sp_track != nil {
		C.sp_track_release(t.sp_track)
		t.sp_track = nil
	}
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
		t.session.session,
		t.sp_track,
	)
	return TrackAvailability(avail)
}

// IsLocal returns true if the track is a local file.
func (t *Track) IsLocal() bool {
	local := C.sp_track_is_local(
		t.session.session,
		t.sp_track,
	)
	return local == 1
}

// IsAutoLinked returns true if the track is auto-linked to another track.
func (t *Track) IsAutoLinked() bool {
	linked := C.sp_track_is_autolinked(
		t.session.session,
		t.sp_track,
	)
	return linked == 1
}

func (t *Track) PlayableTrack() *Track {
	sp_track := C.sp_track_get_playable(
		t.session.session,
		t.sp_track,
	)
	return newTrack(t.session, sp_track)
}

// IsPlaceholder returns true if the track is a
// placeholder. Placeholder tracks are used to store
// other objects than tracks in the playlist. Currently
// this is used in the inbox to store artists, albums and
// playlists.
//
// TODO Use sp_link_create_from_track() to get a link object
// that points to the real object this "track" points to.
func (t *Track) IsPlaceholder() bool {
	placeholder := C.sp_track_is_placeholder(
		t.sp_track,
	)
	return placeholder == 1
}

// IsStarred returns true if the track is starred by the
// currently logged in user.
func (t *Track) IsStarred() bool {
	starred := C.sp_track_is_starred(
		t.session.session,
		t.sp_track,
	)
	return starred == 1
}

// TODO sp_track_set_starred

func (t *Track) Artists() int {
	return int(C.sp_track_num_artists(t.sp_track))
}

func (t *Track) Artist(n int) *Artist {
	if n < 0 || n > t.Artists() {
		panic("spotify: track artist index out of range")
	}
	sp_artist := C.sp_track_artist(t.sp_track, C.int(n))
	return newArtist(sp_artist)
}

func (t *Track) Wait() {
	// TODO make this more elegant and based on callback
	for {
		if t.isLoaded() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (t *Track) isLoaded() bool {
	return C.sp_track_is_loaded(t.sp_track) == 1
}

// Album returns the album of the track.
func (t *Track) Album() *Album {
	sp_album := C.sp_track_album(t.sp_track)
	return newAlbum(sp_album)
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
	sp_album *C.sp_album
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

func newAlbum(sp_album *C.sp_album) *Album {
	C.sp_album_add_ref(sp_album)
	album := &Album{sp_album}
	runtime.SetFinalizer(album, (*Album).finalize)
	return album
}

func (a *Album) finalize() {
	if a.sp_album != nil {
		C.sp_album_release(a.sp_album)
		a.sp_album = nil
	}
}

func (a *Album) Wait() {
	// TODO make perty
	for {
		if a.isLoaded() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (a *Album) IsAvailable() bool {
	return C.sp_album_is_available(a.sp_album) == 1
}

// TODO sp_album_artist
// TODO sp_album_cover

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
	sp_artist *C.sp_artist
}

func newArtist(sp_artist *C.sp_album) *Artist {
	C.sp_artist_add_ref(sp_artist)
	artist := &Artist{sp_artist}
	runtime.SetFinalizer(artist, (*Artist).finalize)
	return artist
}

func (a *Artist) finalize() {
	if a.sp_artist != nil {
		C.sp_artist_release(a.sp_artist)
		a.sp_artist = nil
	}
}

func (a *Artist) isLoaded() bool {
	return C.sp_artist_is_loaded(a.sp_artist) == 1
}

func (a *Artist) Wait() {
	// TODO make perty
	for {
		if a.isLoaded() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (a *Artist) Name() string {
	return C.GoString(C.sp_artist_name(a.sp_artist))
}

// TODO sp_artist_portrait
