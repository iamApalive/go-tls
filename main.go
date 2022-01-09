package main

import (
	"log"

	"github.com/C0d5/go-tls/tls"
)

func main() {
	log.SetFlags(log.Lshortfile)

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn := tls.Client(nil, conf)

	m, _, err := conn.MakeClientHello()
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(m.Marshal())

}
