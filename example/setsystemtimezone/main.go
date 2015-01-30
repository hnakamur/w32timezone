package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/hnakamur/w32syscall"
	"github.com/hnakamur/w32timezone"
)

func getCurrentTimeZoneKeyName() (string, error) {
	var tzi w32syscall.DynamicTimeZoneInformation
	err := w32syscall.GetDynamicTimeZoneInformation(&tzi)
	if err != nil {
		return "", err
	}

	timeZoneKeyName := tzi.TimeZoneKeyName
	return syscall.UTF16ToString(timeZoneKeyName[:]), nil
}

var timeZoneName string

func init() {
	flag.StringVar(&timeZoneName, "s", "", `TimeZone name. (ex: "Tokyo Standard Name")`)
}

func main() {
	flag.Parse()
	if timeZoneName == "" {
		fmt.Println(`Please specify TimeZone name like "Tokyo Standard Name" with double quotes`)
		os.Exit(1)
	}

	origName, err := getCurrentTimeZoneKeyName()
	if err != nil {
		panic(err)
	}
	fmt.Printf("timezone before modification: %s\n", origName)

	tzi, err := w32timezone.BuildDynamicTimeZoneInformation(timeZoneName)
	if err != nil {
		panic(err)
	}
	err = w32timezone.SetSystemTimeZone(tzi)
	if err != nil {
		panic(err)
	}

	name, err := getCurrentTimeZoneKeyName()
	if err != nil {
		panic(err)
	}
	fmt.Printf("timezone after modification: %s\n", name)
}
