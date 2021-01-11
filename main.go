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

func main() {
	initLogger()

	client := core.MakeTLSClient("medium.com", "TLS 1.2", false)
	client.Execute("GET / HTTP/1.1\r\nHost: www.")
	client.Terminate()
}
