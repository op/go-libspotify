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

package libspotify

/*
#cgo pkg-config: libspotify
#include <libspotify/api.h>
*/
import "C"

type Error C.sp_error

func (e Error) Error() string {
	return C.GoString(C.sp_error_message(C.sp_error(e)))
}

const (
	// The library version targeted does not match the one you claim you
	// support
	ErrBadAPIVersion Error = Error(C.SP_ERROR_BAD_API_VERSION)

	// Initialization of library failed - are cache locations etc. valid?
	ErrAPIInitializationFailed = Error(C.SP_ERROR_API_INITIALIZATION_FAILED)

	// The track specified for playing cannot be played
	ErrTrackNotPlayable = Error(C.SP_ERROR_TRACK_NOT_PLAYABLE)

	// The application key is invalid
	ErrBadApplicationKey = Error(C.SP_ERROR_BAD_APPLICATION_KEY)

	// Login failed because of bad username and/or password
	ErrBadUsernameOrPassword = Error(C.SP_ERROR_BAD_USERNAME_OR_PASSWORD)

	// The specified username is banned
	ErrUserBanned = Error(C.SP_ERROR_USER_BANNED)

	// Cannot connect to the Spotify backend system
	ErrUnableToContactServer = Error(C.SP_ERROR_UNABLE_TO_CONTACT_SERVER)

	// Client is too old, library will need to be updated
	ErrClientTooOld = Error(C.SP_ERROR_CLIENT_TOO_OLD)

	// Some other error occurred, and it is permanent (e.g. trying to relogin
	// will not help)
	ErrOtherPermanent = Error(C.SP_ERROR_OTHER_PERMANENT)

	// The user agent string is invalid or too long
	ErrBadUserAgent = Error(C.SP_ERROR_BAD_USER_AGENT)

	// No valid callback registered to handle events
	ErrMissingCallback = Error(C.SP_ERROR_MISSING_CALLBACK)

	// Input data was either missing or invalid
	ErrInvalidIndata = Error(C.SP_ERROR_INVALID_INDATA)

	// Index out of range
	ErrIndexOutOfRange = Error(C.SP_ERROR_INDEX_OUT_OF_RANGE)

	// The specified user needs a premium account
	ErrUserNeedsPremium = Error(C.SP_ERROR_USER_NEEDS_PREMIUM)

	// A transient error occurred.
	ErrOtherTransient = Error(C.SP_ERROR_OTHER_TRANSIENT)

	// The resource is currently loading
	ErrIsLoading = Error(C.SP_ERROR_IS_LOADING)

	// Could not find any suitable stream to play
	ErrNoStreamAvailable = Error(C.SP_ERROR_NO_STREAM_AVAILABLE)

	// Requested operation is not allowed
	ErrPermissionDenied = Error(C.SP_ERROR_PERMISSION_DENIED)

	// Target inbox is full
	ErrInboxIsFull = Error(C.SP_ERROR_INBOX_IS_FULL)

	// Cache is not enabled
	ErrNoCache = Error(C.SP_ERROR_NO_CACHE)

	// Requested user does not exist
	ErrNoSuchUser = Error(C.SP_ERROR_NO_SUCH_USER)

	// No credentials are stored
	ErrNoCredentials = Error(C.SP_ERROR_NO_CREDENTIALS)

	// Network disabled
	ErrNetworkDisabled = Error(C.SP_ERROR_NETWORK_DISABLED)

	// Invalid device ID
	ErrInvalidDeviceId = Error(C.SP_ERROR_INVALID_DEVICE_ID)

	// Unable to open trace file
	ErrCantOpenTraceFile = Error(C.SP_ERROR_CANT_OPEN_TRACE_FILE)

	// This application is no longer allowed to use the Spotify service
	ErrApplicationBanned = Error(C.SP_ERROR_APPLICATION_BANNED)

	// Reached the device limit for number of tracks to download
	ErrOfflineTooManyTracks = Error(C.SP_ERROR_OFFLINE_TOO_MANY_TRACKS)

	// Disk cache is full so no more tracks can be downloaded to offline mode
	ErrOfflineDiskCache = Error(C.SP_ERROR_OFFLINE_DISK_CACHE)

	// Offline key has expired, the user needs to go online again
	ErrOfflineExpired = Error(C.SP_ERROR_OFFLINE_EXPIRED)

	// This user is not allowed to use offline mode
	ErrOfflineNotAllowed = Error(C.SP_ERROR_OFFLINE_NOT_ALLOWED)

	// The license for this device has been lost. Most likely because the user
	// used offline on three other device
	ErrOfflineLicenseLost = Error(C.SP_ERROR_OFFLINE_LICENSE_LOST)

	// The Spotify license server does not respond correctly
	ErrOfflineLicenseError = Error(C.SP_ERROR_OFFLINE_LICENSE_ERROR)

	// A LastFM scrobble authentication error has occurred
	ErrLastFMAuthError = Error(C.SP_ERROR_LASTFM_AUTH_ERROR)

	// An invalid argument was specified
	ErrInvalidArgument = Error(C.SP_ERROR_INVALID_ARGUMENT)

	// An operating system error
	ErrSystemFailure = Error(C.SP_ERROR_SYSTEM_FAILURE)
)

// spError converts an error from libspotify into a Go error.
func spError(err C.sp_error) error {
	if err != C.SP_ERROR_OK {
		return Error(err)
	}
	return nil
}
