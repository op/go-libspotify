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

#include "_cgo_export.h"
#include "libspotify.h"

void set_callbacks(sp_session_callbacks *callbacks)
{
	callbacks->logged_in = cb_logged_in;
	callbacks->logged_out = cb_logged_out;
	callbacks->connection_error = cb_connection_error;
	callbacks->notify_main_thread = cb_notify_main_thread;
	callbacks->log_message = cb_log_message;
	callbacks->credentials_blob_updated = cb_credentials_blob_updated;
	callbacks->connectionstate_updated = cb_connectionstate_updated;
}

void SP_CALLCONV cb_logged_in(sp_session *session, sp_error error)
{
	go_logged_in(session, error);
}

void SP_CALLCONV cb_logged_out(sp_session *session)
{
	go_logged_out(session);
}

void SP_CALLCONV cb_metadata_updated(sp_session *session)
{
	go_metadata_updated(session);
}

void SP_CALLCONV cb_connection_error(sp_session *session, sp_error error)
{
	go_connection_error(session, error);
}

void SP_CALLCONV cb_message_to_user(sp_session *session, const char *message)
{
	go_message_to_user(session, (char *) message);
}

void SP_CALLCONV cb_notify_main_thread(sp_session *session)
{
	go_notify_main_thread(session);
}

void SP_CALLCONV cb_play_token_lost(sp_session *session)
{
	go_play_token_lost(session);
}

void SP_CALLCONV cb_log_message(sp_session *session, const char *data)
{
	go_log_message(session, (char *) data);
}

void SP_CALLCONV cb_streaming_error(sp_session *session, sp_error error)
{
	go_streaming_error(session, error);
}

void SP_CALLCONV cb_offline_error(sp_session *session, sp_error error)
{
	go_offline_error(session, error);
}

void SP_CALLCONV cb_credentials_blob_updated(sp_session *session, const char *blob)
{
	go_credentials_blob_updated(session, (char *) blob);
}

void SP_CALLCONV cb_connectionstate_updated(sp_session *session)
{
	go_connectionstate_updated(session);
}

void SP_CALLCONV cb_scrobble_error(sp_session *session, sp_error error)
{
	go_scrobble_error(session, error);
}

void SP_CALLCONV cb_private_session_mode_changed(sp_session *session, bool is_private)
{
	go_private_session_mode_changed(session, is_private);
}

sp_search* search_create(sp_session *session, const char *query, int track_offset, int track_count, int album_offset, int album_count, int artist_offset, int artist_count, int playlist_offset, int playlist_count, sp_search_type search_type, void *userdata)
{
	return sp_search_create(
		session, query,
		track_offset, track_count,
		album_offset, album_count,
		artist_offset, artist_count,
		playlist_offset, playlist_count,
		search_type, cb_search_complete,
		userdata
	);
}

void SP_CALLCONV cb_search_complete(sp_search *search, void *userdata)
{
	go_search_complete(search, userdata);
}

sp_toplistbrowse* toplistbrowse_create(sp_session *session, sp_toplisttype type, sp_toplistregion region, const char *username, void *userdata)
{
	return sp_toplistbrowse_create(
		session, type, region, username,
		cb_toplistbrowse_complete, userdata
	);
}

void SP_CALLCONV cb_toplistbrowse_complete(sp_toplistbrowse *toplist, void *userdata)
{
	go_toplistbrowse_complete(toplist, userdata);
}
