// Package cmdutil holds small scaffolding shared by nostrhost-control's
// command-line binaries (cmd/nostrhost-control, cmd/nostrhost-notify): the
// signal-driven shutdown context both main()s build, and the
// fatal-on-error pattern both use while loading startup config.
package cmdutil

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// SignalContext returns a context cancelled on SIGINT/SIGTERM, and the
// matching stop function the caller must defer.
func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// FatalIfErr logs err prefixed with prefix and exits the process
// (log.Fatalf) if err is non-nil — the fatal-on-config-load-error
// scaffolding both binaries repeat at startup.
func FatalIfErr(prefix string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", prefix, err)
	}
}
