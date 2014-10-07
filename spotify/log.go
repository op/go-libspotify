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
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	errLogInvalidFormat = errors.New("spotify: invalid log message")
)

// logMessageRe is used to parse the log message from libspotify after the
// timestamp (15:04:05.999) in the format:
// 	D [module:line] message
var logMessageRe = regexp.MustCompile(`^([\dA-Z]) \[([^ \]]+)\s*\] (.*)[\n]*$`)

type LogLevel int

const (
	LogFatal LogLevel = iota
	LogError
	LogWarning
	LogInfo
	LogDebug
)

var logLevels = map[string]LogLevel{
	"F": LogFatal,
	"E": LogError,
	"W": LogWarning,
	"I": LogInfo,
	"D": LogDebug,
}

type LogMessage struct {
	Time    time.Time
	Level   LogLevel
	Module  string
	Message string
}

func (l *LogMessage) String() string {
	return fmt.Sprintf("[%s] %s", l.Module, l.Message)
}

// parseLogMessage will parse libspotify generated log messages into LogMessage
// and return any error if it failed. This function might return a usable log
// message together with an error, which might indicate that just some of the
// fields failed to be parsed.
//
// The full format of the log message is:
// 15:04:05.999 D [module:line] message
func parseLogMessage(line string) (*LogMessage, error) {
	var tsLayout = "15:04:05.999"

	// The time and the rest is separated by a space. Parse them individually.
	pos := strings.Index(line, " ")
	if pos != len(tsLayout) && len(line) < pos+1 {
		return nil, errLogInvalidFormat
	}
	ts := line[0:pos]
	unparsed := line[pos+1:]

	// Parse the timestamp, which is reported in local time. If the difference
	// between the current time and the parsed time is too big, we assume that
	// the reported time is for the previous day.
	now := time.Now()
	t, err := time.ParseInLocation(tsLayout, ts, time.Local)
	if err != nil {
		return nil, err
	}
	t = t.AddDate(now.Year(), int(now.Month())-1, now.Day()-1)
	if t.Hour() > now.Hour() {
		t = t.Add(-24 * time.Hour)
	}

	m := logMessageRe.FindStringSubmatch(unparsed)
	if m == nil {
		return nil, errLogInvalidFormat
	}
	strLevel := m[1]
	module := strings.Trim(m[2], " ")
	message := strings.Trim(m[3], " ")

	level, exists := logLevels[strLevel]
	if !exists {
		level = LogError
		err = fmt.Errorf("spotify: unknown log level: %s", strLevel)
	}

	return &LogMessage{t, level, module, message}, err
}
