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

void SP_CALLCONV cb_connection_error(sp_session *session, sp_error error)
{
	go_connection_error(session, error);
}

void SP_CALLCONV cb_notify_main_thread(sp_session *session)
{
	go_notify_main_thread(session);
}

void SP_CALLCONV cb_log_message(sp_session *session, const char *data)
{
	go_log_message(session, (char *) data);
}

void SP_CALLCONV cb_credentials_blob_updated(sp_session *session, const char *blob)
{
	go_credentials_blob_updated(session, (char *) blob);
}

void SP_CALLCONV cb_connectionstate_updated(sp_session *session)
{
	go_connectionstate_updated(session);
}
