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

#ifndef __GO_LIBSPOTIFY_H
#define __GO_LIBSPOTIFY_H

#include <stdlib.h>
#include <libspotify/api.h>

sp_session_config* sp_session_config_new();
void sp_session_config_free(sp_session_config *config);
void set_callbacks(sp_session_callbacks*);

void SP_CALLCONV cb_logged_in(sp_session *session, sp_error error);
void SP_CALLCONV cb_logged_out(sp_session *session);
// void SP_CALLCONV cb_metadata_updated(sp_session *session);
void SP_CALLCONV cb_connection_error(sp_session *session, sp_error error);
// void SP_CALLCONV cb_message_to_user(sp_session *session, const char *message);
void SP_CALLCONV cb_notify_main_thread(sp_session *session);
// void SP_CALLCONV cb_music_delivery(sp_session *session, const sp_audioformat *format, const void *frames, int num_frames);
// void SP_CALLCONV cb_play_token_lost(sp_session *session);
void SP_CALLCONV cb_log_message(sp_session *session, const char *data);
// void SP_CALLCONV cb_end_of_track(sp_session *session);
// void SP_CALLCONV cb_streaming_error(sp_session *session, sp_error error);
// void SP_CALLCONV cb_userinfo_updated(sp_session *session);
// void SP_CALLCONV cb_start_playback(sp_session *session);
// void SP_CALLCONV cb_stop_playback(sp_session *session);
// void SP_CALLCONV cb_get_audio_buffer_stats(sp_session *session, sp_audio_buffer_stats *stats);
// void SP_CALLCONV cb_offline_status_updated(sp_session *session);
// void SP_CALLCONV cb_offline_error(sp_session *session, sp_error error);
void SP_CALLCONV cb_credentials_blob_updated(sp_session *session, const char *blob);
void SP_CALLCONV cb_connectionstate_updated(sp_session *session);
// void SP_CALLCONV cb_scrobble_error(sp_session *session, sp_error error);
// void SP_CALLCONV cb_private_session_mode_changed(sp_session *session, bool is_private);

#endif // __GO_LIBSPOTIFY_H
