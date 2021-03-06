package main

import (
	"fmt"
	"github.com/urfave/cli"
	"io"
	"os"
	"strings"
)

/*
* version will be populated by the Makefile, read from
* VERSION file of the source code.
 */
var version = "0.0.1"

/*
* gitCommit will be the hash that the binary was built from
* and will be populated by the Makefile.
 */
var gitCommit = ""

const usage = "shelter as a remote attestation tool for workload runing in enclave containers."

func main() {
	app := cli.NewApp()
	app.Name = "shelter"
	app.Usage = usage

	var ver []string
	if version != "" {
		ver = append(ver, version)
	}
	if gitCommit != "" {
		ver = append(ver, fmt.Sprintf("commit: %s", gitCommit))
	}
	app.Version = strings.Join(ver, "\n")

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose",
			Usage: "enable verbose output",
		},
	}

	app.Commands = []cli.Command{
		sgxraCommand,
		mrverifyCommand,
	}

	app.Before = func(context *cli.Context) error {
		if context.GlobalBool("verbose") {
		}
		return nil
	}

	/* If the command returns an error, cli takes upon itself to print
	* the error on cli.ErrWriter and exit.
	* Use our own writer here to ensure the log gets sent to the right location.
	 */
	cli.ErrWriter = &FatalWriter{cli.ErrWriter}
	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}

type FatalWriter struct {
	cliErrWriter io.Writer
}

func (f *FatalWriter) Write(p []byte) (n int, err error) {
	return f.cliErrWriter.Write(p)
}

/*
* fatal prints the error's details if it is a libcontainer specific error type
* then exits the program with an exit status of 1.
 */
func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
