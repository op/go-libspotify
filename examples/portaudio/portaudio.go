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

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"time"

	"code.google.com/p/portaudio-go/portaudio"
	"github.com/op/go-libspotify/spotify"
)

var (
	appKeyPath = flag.String("key", "spotify_appkey.key", "path to app.key")
	username   = flag.String("username", "o.p", "spotify username")
	password   = flag.String("password", "", "spotify password")
	debug      = flag.Bool("debug", false, "debug output")
)

type audio struct {
	format spotify.AudioFormat
	frames []byte
}

type audio2 struct {
	format spotify.AudioFormat
	frames []int16
}

type portAudio struct {
	buffer chan *audio
}

func newPortAudio() *portAudio {
	return &portAudio{
		buffer: make(chan *audio, 8),
	}
}

func (pa *portAudio) WriteAudio(format spotify.AudioFormat, frames []byte) int {
	audio := &audio{format, frames}
	println("audio", len(frames), len(frames)/2)

	if len(frames) == 0 {
		println("no frames")
		return 0
	}

	select {
	case pa.buffer <- audio:
		println("return", len(frames))
		return len(frames)
	default:
		println("buffer full")
		return 0
	}
}

func (pa *portAudio) player() {
	out := make([]int16, 2048*2)

	stream, err := portaudio.OpenDefaultStream(
		0,
		2,     // audio.format.Channels,
		44100, // float64(audio.format.SampleRate),
		len(out),
		&out,
	)
	if err != nil {
		panic(err)
	}
	defer stream.Close()

	stream.Start()
	defer stream.Stop()

	// Decode the incoming data which is expected to be 2 channels and
	// delivered as int16 in []byte, hence we need to convert it.
	for audio := range pa.buffer {
		if len(audio.frames) != 2048*2*2 {
			panic("unexpected")
		}

		j := 0
		for i := 0; i < len(audio.frames); i += 2 {
			out[j] = int16(audio.frames[i]) | int16(audio.frames[i+1])<<8
			j++
		}

		stream.Write()
	}
}

func main() {
	flag.Parse()
	prog := path.Base(os.Args[0])

	portaudio.Initialize()
	defer portaudio.Terminate()

	uri := "spotify:track:5C4iS9W81NM5Rp0TW0TZ4o"
	if flag.NArg() == 1 {
		uri = flag.Arg(0)
	}

	appKey, err := ioutil.ReadFile(*appKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	pa := newPortAudio()
	go pa.player()

	session, err := spotify.NewSession(&spotify.Config{
		ApplicationKey:   appKey,
		ApplicationName:  prog,
		CacheLocation:    "tmp",
		SettingsLocation: "tmp",
		AudioConsumer:    pa,

		// Disable playlists to make playback faster
		DisablePlaylistMetadataCache: true,
		InitiallyUnloadPlaylists:     true,
	})
	if err != nil {
		log.Fatal(err)
	}

	credentials := spotify.Credentials{
		Username: *username,
		Password: *password,
	}
	if err = session.Login(credentials, false); err != nil {
		log.Fatal(err)
	}

	// Log messages
	if *debug {
		go func() {
			for msg := range session.LogMessages() {
				log.Print(msg)
			}
		}()
	}

	// Wait for login and expect it to go fine
	if err = <-session.LoggedInUpdates(); err != nil {
		log.Fatal(err)
	}

	// Parse the track
	link, err := session.ParseLink(uri)
	if err != nil {
		log.Fatal(err)
	}
	track, err := link.Track()
	if err != nil {
		log.Fatal(err)
	}

	// Load the track and play it
	track.Wait()
	player := session.Player()
	if err := player.Load(track); err != nil {
		fmt.Println("%#v", err)
		log.Fatal(err)
	}

	player.Play()

	for {
		time.Sleep(100 * time.Millisecond)
	}
}
