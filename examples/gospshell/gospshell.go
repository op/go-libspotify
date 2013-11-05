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
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"time"

	sp "github.com/op/go-libspotify"
)

var (
	appKeyPath = flag.String("key", "spotify_appkey.key", "path to app.key")
	username   = flag.String("username", "o.p", "spotify username")
	password   = flag.String("password", "", "spotify password")
	remember   = flag.Bool("remember", false, "remember username and password")
)

// command is the declaration for running a command.
type command func(*sp.Session, []string, <-chan bool) error

// commands contains all available commands.
var commands = map[string]command{
	"search":  cmdSearch,
	"toplist": cmdToplist,
}

var reCommand = regexp.MustCompile(`\s+`)

func main() {
	flag.Parse()
	prog := path.Base(os.Args[0])

	appKey, err := ioutil.ReadFile(*appKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	println("libspotify", sp.BuildId())
	session, err := sp.NewSession(&sp.Config{
		ApplicationKey:   appKey,
		ApplicationName:  prog,
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

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%s:> ", prog)
		if !scanner.Scan() {
			break
		}

		line := strings.Trim(scanner.Text(), " ")
		args := reCommand.Split(line, -1)
		fmt.Println("%#v", args)
		if len(args) == 0 || args[0] == "" {
			continue
		}
		cmd := commands[args[0]]
		if cmd == nil {
			fmt.Fprintf(os.Stderr, "%s: unknown command: %s\n", prog, args[0])
			cmd = cmdHelp
		}

		if err := cmd(session, args, nil); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", args[0], err)
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	os.Exit(32)

	// TODO incorporate signal handling etc
	exitAttempts := 0
	running := true
	for running {
		println("waiting for connection state change", session.ConnectionState())

		select {
		case message := <-session.LogMessages():
			println("!! log message", message)
		case <-session.ConnectionStateUpdates():
			println("!! connstate", session.ConnectionState())
		case err := <-session.LoginUpdates():
			println("!! login updated", err)
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

func trackStr(track *sp.Track) string {
	track.Wait()

	var artists []string
	for i := 0; i < track.Artists(); i++ {
		artists = append(artists, track.Artist(i).Name())
	}
	return fmt.Sprintf("%s ♫ %s ❂ %s ♪ %s",
		track.Link(),
		strings.Join(artists, ", "),
		track.Album().Name(),
		track.Name(),
	)
}

func albumStr(album *sp.Album) string {
	album.Wait()
	return fmt.Sprintf("%s ♫ %s ❂ %s",
		album.Link(),
		album.Artist().Name(),
		album.Name(),
	)
}

func artistStr(artist *sp.Artist) string {
	artist.Wait()
	return fmt.Sprintf("%s ♫ %s",
		artist.Link(),
		artist.Name(),
	)
}

// cmdHelp displays available commands.
func cmdHelp(session *sp.Session, args []string, abort <-chan bool) error {
	println("use <command> -h for more information")
	for command := range commands {
		println(" - ", command)
	}
	return nil
}

// cmdSearch searches for music.
func cmdSearch(session *sp.Session, args []string, abort <-chan bool) error {
	var f = flag.NewFlagSet(args[0], flag.ContinueOnError)
	opts := struct {
		track, album, artist, playlist *bool
		offset, limit                  *int
	}{
		track:    f.Bool("track", false, "include tracks"),
		album:    f.Bool("album", false, "include albums"),
		artist:   f.Bool("artist", false, "include artists"),
		playlist: f.Bool("playlist", false, "include playlists"),

		offset: f.Int("offet", 0, "result offet"),
		limit:  f.Int("limit", 10, "result count limitation"),
	}

	if err := f.Parse(args[1:]); err != nil {
		return err
	} else if f.NArg() == 0 {
		return errors.New("expected query string")
	}

	// Set all values to true if none are request.
	if !*opts.track && !*opts.album && !*opts.artist && !*opts.playlist {
		*opts.track = true
		*opts.album = true
		*opts.artist = true
		*opts.playlist = true
	}

	query := strings.Join(f.Args(), " ")

	var sOpts sp.SearchOptions
	spec := sp.SearchSpec{*opts.offset, *opts.limit}

	if *opts.track {
		sOpts.Tracks = spec
	}
	if *opts.album {
		sOpts.Albums = spec
	}
	if *opts.artist {
		sOpts.Artists = spec
	}
	if *opts.playlist {
		sOpts.Playlists = spec
	}

	// TODO cancel wait when abort<-true
	search, err := session.Search(query, &sOpts)
	if err != nil {
		return err
	}
	search.Wait()

	println("###done searching", search.Tracks(), search.TotalTracks(), search.Query(), search.Link().String())

	for i := 0; i < search.Tracks(); i++ {
		println(trackStr(search.Track(i)))
	}
	for i := 0; i < search.Albums(); i++ {
		println(albumStr(search.Album(i)))
	}
	for i := 0; i < search.Artists(); i++ {
		println(artistStr(search.Artist(i)))
	}
	// TODO playlist

	return nil
}

// cmdToplist displays toplists based on region and entity.
func cmdToplist(session *sp.Session, args []string, abort <-chan bool) error {
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	opts := struct {
		track, album, artist *bool
		user                 *bool
		offset, limit        *int
	}{
		track:  f.Bool("track", false, "include tracks"),
		album:  f.Bool("album", false, "include albums"),
		artist: f.Bool("artist", false, "include artists"),

		user: f.Bool("user", false, "query for username instead of region"),

		offset: f.Int("offet", 0, "result offet"),
		limit:  f.Int("limit", 10, "result count limitation"),
	}

	if err := f.Parse(args[1:]); err != nil {
		return err
	} else if f.NArg() > 1 {
		return errors.New("too many arguments")
	}

	// Set all values to true if none are request.
	if !*opts.track && !*opts.album && !*opts.artist {
		*opts.track = true
		*opts.album = true
		*opts.artist = true
	}

	var user *sp.User
	var region = sp.ToplistRegionEverywhere

	if *opts.user {
		var err error
		if f.NArg() == 1 {
			user, err = session.GetUser(f.Arg(0))
		} else {
			user, err = session.CurrentUser()
		}
		if err != nil {
			return err
		}
		user.Wait()
	} else {
		if f.NArg() > 0 {
			var err error
			if region, err = sp.NewToplistRegion(f.Arg(0)); err != nil {
				return errors.New("Either specify country (eg. SE) or * for worldwide")
			}
		}
	}

	if *opts.track {
		var toplist *sp.TracksToplist
		if *opts.user {
			toplist = user.TracksToplist()
		} else {
			toplist = session.TracksToplist(region)
		}
		toplist.Wait()
		println("tracks toplist loaded", region.String(), toplist.Duration().String())
		for i := *opts.offset; i < toplist.Tracks() && i < *opts.limit; i++ {
			println(trackStr(toplist.Track(i)))
		}
	}
	if *opts.album {
		var toplist *sp.AlbumsToplist
		if *opts.user {
			toplist = user.AlbumsToplist()
		} else {
			toplist = session.AlbumsToplist(region)
		}
		toplist.Wait()
		println("albums toplist loaded", region.String(), toplist.Duration().String())
		for i := *opts.offset; i < toplist.Albums() && i < *opts.limit; i++ {
			println(albumStr(toplist.Album(i)))
		}
	}
	if *opts.artist {
		var toplist *sp.ArtistsToplist
		if *opts.user {
			toplist = user.ArtistsToplist()
		} else {
			toplist = session.ArtistsToplist(region)
		}
		toplist.Wait()
		println("artists toplist loaded", region.String(), toplist.Duration().String())
		for i := *opts.offset; i < toplist.Artists() && i < *opts.limit; i++ {
			println(artistStr(toplist.Artist(i)))
		}
	}

	return nil
}
