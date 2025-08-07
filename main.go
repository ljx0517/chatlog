package main

import (
	"github.com/sjzar/chatlog/cmd/chatlog"
	"log"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	chatlog.Execute()
}
