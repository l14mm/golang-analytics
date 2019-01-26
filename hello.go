package main

import (
	"fmt"
	"os"
	"os/signal"
	"log"
	"syscall"
    "encoding/json"
	"github.com/dghubble/oauth1"
	"github.com/dghubble/go-twitter/twitter"
)

type Configuration struct {
    api_key string
    api_secret string
    access_token_key string
    access_token_secret string
}

func main() {
	// Load config variables
	file, _ := os.Open("conf.json")
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}

	config := oauth1.NewConfig(configuration.api_key, configuration.api_secret)
	token := oauth1.NewToken(configuration.access_token_key, configuration.access_token_secret)
	httpClient := config.Client(oauth1.NoContext, token)

	// Twitter client
	client := twitter.NewClient(httpClient)
	demux := twitter.NewSwitchDemux()

	// Print tweets received from stream
	demux.Tweet = func(tweet *twitter.Tweet) {
		fmt.Println(tweet.Text)
	}

	params := &twitter.StreamSampleParams{
		StallWarnings: twitter.Bool(true),
	}

	// Get a sample stream of tweets
	stream, err := client.Streams.Sample(params)

	// Get demux to handle stream of tweets
	go demux.HandleChan(stream.Messages)

	// Wait for SIGINT and SIGTERM (HIT CTRL-C)
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	log.Println(<-ch)
	log.Println(err)

	stream.Stop()
}
