package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/viorelyo/tlsExperiment/core"
)

func initLogger() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
}

// TODO dump each part of handshake to JSON file
func main() {
	initLogger()

	client := core.MakeTLSClient("tools.ietf.org", false)
	client.Execute()
	client.Terminate()
}
