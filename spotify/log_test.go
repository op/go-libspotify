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

package spotify

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

// newLogMessage creates a log message with the current dates timestamp at
// 00:00:00, with the time diff applied to it.
func newLogMessage(diff time.Duration, level LogLevel, module, message string) *LogMessage {
	t := time.Now().Round(time.Hour)
	t = t.Add(-1 * time.Duration(t.Hour()) * time.Hour)
	msg := &LogMessage{
		Time:    t.Add(diff),
		Level:   level,
		Module:  module,
		Message: message,
	}
	return msg
}

func TestNewLogMessage(t *testing.T) {
	var tests = []struct {
		line     string
		expected *LogMessage
		err      error
	}{
		{
			line: `23:59:00.123 F [ap:1226                  ] Send SPDY query (2) 'http://playlist/user/o.p/playlist/' (DIFF)
`,
			expected: newLogMessage(
				-1*(59*time.Second+877*time.Millisecond),
				LogFatal,
				"ap:1226",
				"Send SPDY query (2) 'http://playlist/user/o.p/playlist/' (DIFF)",
			),
		},
		{
			line: `00:00:01.001 E [ap:1226] `,
			expected: newLogMessage(
				1*time.Second+1*time.Millisecond,
				LogError,
				"ap:1226",
				"",
			),
		},
		{
			line: `00:00:01.001 W [ap:1226] `,
			expected: newLogMessage(
				1*time.Second+1*time.Millisecond,
				LogWarning,
				"ap:1226",
				"",
			),
		},
		{
			line: `00:00:01.001 I [ap:1226] `,
			expected: newLogMessage(
				1*time.Second+1*time.Millisecond,
				LogInfo,
				"ap:1226",
				"",
			),
		},
		{
			line: `00:00:01.001 D [ap:343] ChannelError(1, 1, link-tracks)`,
			expected: newLogMessage(
				1*time.Second+1*time.Millisecond,
				LogDebug,
				"ap:343",
				"ChannelError(1, 1, link-tracks)",
			),
		},
		{
			line: `00:00:01.001 X [ap:1226] `,
			expected: newLogMessage(
				1*time.Second+1*time.Millisecond,
				LogError,
				"ap:1226",
				"",
			),
			err: errors.New("spotify: unknown log level: X"),
		},
		{
			line: `00:00:01.001 D `,
			err:  errLogInvalidFormat,
		},
	}

	for _, test := range tests {
		m, err := parseLogMessage(test.line)

		// Convert errors to string since errors.New("") != errors.New("")
		if err != test.err && err.Error() != test.err.Error() {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(m, test.expected) {
			t.Errorf("%#v != %#v", m, test.expected)
		}
	}
}
