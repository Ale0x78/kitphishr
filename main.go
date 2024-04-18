package main

import (
	"flag"
	"fmt"
	"github.com/gookit/color"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	userAgent         = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
	MAX_DOWNLOAD_SIZE = 104857600 // 100mb
)

var verbose bool
var downloadKits bool
var concurrency int
var to int
var defaultOutputDir string
var ua string
var index *os.File

func hasSuffixes(target string, suffixes []string) bool{
	for _, suffix := range suffixes {
		if strings.HasSuffix(target, suffix) {
			return true
		}
	}
	return false
}

func containsSubstringsAny(target string, substrings []string) bool{
	for _, substring := range substrings {
		if strings.Contains(target, substring) {
			return true
		}
	}
	return false
}

func main() {

	flag.IntVar(&concurrency, "c", 50, "set the concurrency level")
	flag.IntVar(&to, "t", 45, "set the connection timeout in seconds (useful to ensure the download of large files)")
	flag.BoolVar(&verbose, "v", false, "get more info on URL attempts")
	flag.BoolVar(&downloadKits, "d", false, "option to download suspected phishing kits")
	flag.StringVar(&ua, "u", userAgent, "User-Agent for requests")
	flag.StringVar(&defaultOutputDir, "o", "kits", "directory to save output files")

	flag.Parse()

	client := MakeClient()

	targets := make(chan string)
	responses := make(chan Response)
	tosave := make(chan Response)

	// create the output directory, ready to save files to
	if downloadKits {
		err := os.MkdirAll(defaultOutputDir, os.ModePerm)
		if err != nil {
			fmt.Printf("There was an error creating the output directory : %s\n", err)
			os.Exit(1)
		}
		// open the index file
		indexFile := filepath.Join(defaultOutputDir, "/index")
		index, err = os.OpenFile(indexFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open index file for writing: %s\n", err)
			os.Exit(1)
		}
	}

	// worker group to fetch the urls from targets channel
	// send the output to responses channel for further processing
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {

		wg.Add(1)

		go func() {

			defer wg.Done()

			for url := range targets {
				if verbose {
					fmt.Printf("Attempting %s\n", url)
				}
				res, err := AttemptTarget(client, url)
				if err != nil {
					continue
				}

				responses <- res
			}

		}()

	}

	// response group
	// determines if we've found a zip from a url folder
	// or if we've found an open directory and looks for a zip within
	var rg sync.WaitGroup

	for i := 0; i < concurrency/2; i++ {

		rg.Add(1)

		go func() {

			defer rg.Done()

			for resp := range responses {

				if resp.StatusCode != http.StatusOK {
					continue
				}

				requrl := resp.URL
				// .tar, .bz2, .gz, .7z, .tar.gz, .tgz, .tar.Z, .tar.bz2, .tbz2, .tar.lz, .tlz, .tar.xz, .txz, .tar.zst
				// Expand to all of the types above
				// if we found a zip from a URL path
				if hasSuffixes(requrl, []string{".tar", ".bz2", ".gz", ".7z", ".tar.gz", ".tgz", ".tar.Z", ".tar.bz2", ".tbz2", ".tar.lz", ".tlz", ".tar.xz", ".txz", ".tar.zst"}) {

					// make sure it's a valid archive file
					if resp.ContentLength > 0 && resp.ContentLength < MAX_DOWNLOAD_SIZE && containsSubstringsAny(resp.ContentType, []string{"zip", "tar", "gz", "bz", "7z"}) {

						if verbose {
							color.Green.Printf("archive file found from URL folder at %s\n", requrl)
						} else {
							fmt.Println(requrl)
						}

						// download the zip
						if downloadKits {
							tosave <- resp
							continue
						}
					}
				}

				// check if we've found an open dir containing a zip
				hrefs, err := ZipFromDir(resp)
				if err != nil {
					continue
				}
				// iterate the slice of hrefs
				for _, href := range hrefs {

					if href != "" {
						hurl := ""
						if strings.HasSuffix(requrl, "/") {
							hurl = requrl + href
						} else {
							hurl = requrl + "/" + href
						}
						if verbose {
							color.Green.Printf("Zip found from Open Directory at %s\n", hurl)
						} else {
							fmt.Println(hurl)
						}
						if downloadKits {
							resp, err := AttemptTarget(client, hurl)
							if err != nil {
								if verbose {
									color.Red.Printf("There was an error downloading %s : %s\n", hurl, err)
								}
								continue
							}
							tosave <- resp
							continue
						}
					}
				}
			}
		}()
	}

	// save group
	var sg sync.WaitGroup

	// give this a few threads to play with
	for i := 0; i < 10; i++ {

		sg.Add(1)

		go func() {
			defer sg.Done()
			for resp := range tosave {
				filename, err := resp.SaveResponse()
				if err != nil {
					if verbose {
						color.Red.Printf("There was an error saving %s : %s\n", resp.URL, err)
					}
					continue
				} else if filename != "" {
					if verbose {
						color.Yellow.Printf("Successfully saved %s\n", filename)
					}
					// update the index file
					t := time.Now()
					line := fmt.Sprintf("%s,%s,%s\n", t.Format("20060102150405"), resp.URL, filename)
					fmt.Fprintf(index, "%s", line)
				}
			}
		}()
	}

	// get input either from user or phishtank
	input, err := GetUserInput()
	if err != nil {
		fmt.Printf("There was an error getting URLS from PhishTank.\n")
		os.Exit(3)
	}

	// generate targets based on user input
	urls := GenerateTargets(input)

	// send target urls to target channel
	for url := range urls {
		targets <- url
	}

	close(targets)
	wg.Wait()

	close(responses)
	rg.Wait()

	close(tosave)
	sg.Wait()

}
