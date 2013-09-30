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
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"time"

	sp "github.com/op/go-libspotify"
)

var (
	appKeyPath = flag.String("key", "spotify_appkey.key", "path to app.key")
	username   = flag.String("username", "o.p", "spotify username")
	password   = flag.String("password", "", "spotify password")
	remember   = flag.Bool("remember", false, "remember username and password")
)

func main() {
	flag.Parse()

	appKey, err := ioutil.ReadFile(*appKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	session, err := sp.NewSession(&sp.Config{
		ApplicationKey:   appKey,
		ApplicationName:  "gospshell",
		CacheLocation:    "tmp",
		SettingsLocation: "tmp",
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = session

	exit := make(chan bool)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, os.Kill)
	go func() {
		for _ = range signals {
			select {
			case exit <- true:
			default:
			}
		}
	}()

	if len(*password) > 0 {
		credentials := sp.Credentials{
			Username: *username,
			Password: *password,
		}
		if err = session.Login(credentials, *remember); err != nil {
			log.Fatal(err)
		}
	} else {
		if err = session.Relogin(); err != nil {
			log.Fatal(err)
		}
	}

	exitAttempts := 0
	running := true
	for running {
		println("waiting for connection state change", session.ConnectionState())

		select {
		case <-session.ConnectionStateUpdates():
			println("!! connstate", session.ConnectionState())
		case err := <-session.LoginUpdates():
			go func() {
				time.Sleep(2 * time.Second)
				println("!! login updated", err)
				opts := sp.SearchOptions{
					Track:    sp.SearchSpec{0, 100},
					Album:    sp.SearchSpec{0, 100},
					Artist:   sp.SearchSpec{0, 100},
					Playlist: sp.SearchSpec{0, 100},
				}
				search := session.Search("nasum", &opts)
				search.Wait()
				println("###done searching", search.Tracks(), search.TotalTracks(), search.Query())

				for i := 0; i < search.Tracks(); i++ {
					track := search.Track(i)
					track.Wait()
					println("track", i, track.Name())
				}
			}()

		case <-session.LogoutUpdates():
			println("!! logout updated")
			running = false
		case _ = <-session.CredentialsBlobUpdates():
			println("!! blob updated")
		case <-exit:
			println("!! exiting")
			if exitAttempts >= 3 {
				os.Exit(42)
			}
			exitAttempts++
			session.Logout()
		case <-time.After(5 * time.Second):
			println("state change timeout")
		}
	}

	session.Close()
}
