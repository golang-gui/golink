package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/golang-gui/golink"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "golink:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("golink " + golink.Version)
		return nil
	}
	request := flag.String("request", "", "versioned native link request JSON")
	flag.Parse()
	if *request == "" || flag.NArg() != 0 {
		return fmt.Errorf("expected -request file.json")
	}
	f, err := os.Open(*request)
	if err != nil {
		return err
	}
	r, err := golink.ReadRequest(f)
	f.Close()
	if err != nil {
		return err
	}
	return golink.Link(r)
}
