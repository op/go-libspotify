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

	CacheLocation string
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

	// mu is the mutex used when accessing sessions.
	mu sync.RWMutex

	// sessions is a set of all sessions currently active. Its purpose is
	// to add an additional safety mechanism before calling into Go code.
	//
	// libspotify does currently only support one active session per process.
	// This binding does not enforce this limitation and lets the library handle
	// its flaws by itself.
	sessions = make(map[*Session]bool)
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

	events chan event

	credentialsBlobs chan []byte
	states           chan struct{}
	loggedIn         chan error
	loggedOut        chan struct{}

	wg      sync.WaitGroup
	dealloc sync.Once
}

// sessionCall maps the C Spotify session structure to the Go session and
// executes the given function if it can find it. If the session is unknown,
// it is silently ignored.
func sessionCall(spSession unsafe.Pointer, callback func(*Session)) error {
	s := (*C.sp_session)(spSession)
	session := (*Session)(C.sp_session_userdata(s))
	if session == nil {
		panic("spotify: no session found")
		// return errors.New("spotify: no session found")
	}

	mu.RLock()
	defer mu.RUnlock()
	if !sessions[session] {
		panic("spotify: not a valid session")
		// return fmt.Errorf("spotify: not a valid session: %p", session)
	}
	callback((*Session)(session))
	return nil
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

	// Register the session as a valid session receiving callbacks.
	mu.Lock()
	sessions[session] = true
	mu.Unlock()

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

	// Remove the session again if an error is encountered.
	if err := <-errc; err != nil {
		mu.Lock()
		delete(sessions, session)
		mu.Unlock()
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

		mu.Lock()
		delete(sessions, s)
		mu.Unlock()

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

	rc := C.sp_session_login(
		s.session,
		cusername,
		cpassword,
		crememberme,
		cblob,
	)
	return spError(rc)
}

// ReLogin logs the remembered user in if the last user which logged in, logged
// in with the remember flag set to true.
//
// If no credentials are stored, this will return ErrNoCredentials.
func (s *Session) ReLogin() error {
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

func (s *Session) processEvents() {
	var nextTimeoutMs C.int

	s.wg.Add(1)
	defer s.wg.Done()

	for {
		rc := C.sp_session_process_events(s.session, &nextTimeoutMs)
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
