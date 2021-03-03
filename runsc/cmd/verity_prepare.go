// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// VerityPrepare implements subcommands.Commands for the "verity-prepare"
// command. It sets up a sandbox with a writable verity mount mapped to "--dir",
// and executes the verity measure tool specified by "--tool" in the sandbox. It
// is intended to prepare --dir to be mounted as a verity filesystem.
type VerityPrepare struct {
	root string
	cwd  string
	tool string
	dir  string
}

// Name implements subcommands.Command.Name.
func (*VerityPrepare) Name() string {
	return "verity-prepare"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*VerityPrepare) Synopsis() string {
	return "Generates the data structures necessary to enable verityfs on a filesystem."
}

// Usage implements subcommands.Command.Usage.
func (*VerityPrepare) Usage() string {
	return "verity-prepare --tool=<measure_tool> --dir=<path>"
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *VerityPrepare) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.root, "root", "/", `path to the root directory, defaults to "/"`)
	f.StringVar(&c.cwd, "cwd", ".", "path to the current directory, defaults to the current directory")
	f.StringVar(&c.tool, "tool", "", "path to the verity measure_tool")
	f.StringVar(&c.dir, "dir", "", "path to the directory to hash")
}

// Execute implements subcommands.Command.Execute.
func (c *VerityPrepare) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	conf := args[0].(*config.Config)
	waitStatus := args[1].(*unix.WaitStatus)

	hostname, err := os.Hostname()
	if err != nil {
		return Errorf("Error to retrieve hostname: %v", err)
	}

	// Map the entire host file system.
	absRoot, err := resolvePath(c.root)
	if err != nil {
		return Errorf("Error resolving root: %v", err)
	}
	absCwd, err := resolvePath(c.cwd)
	if err != nil {
		return Errorf("Error resolving current directory: %v", err)
	}

	spec := &specs.Spec{
		Root: &specs.Root{
			Path: absRoot,
		},
		Process: &specs.Process{
			Cwd:          absCwd,
			Args:         []string{c.tool, "--path", "/verityroot"},
			Env:          os.Environ(),
			Capabilities: specutils.AllCapabilities(),
		},
		Hostname: hostname,
		Mounts: []specs.Mount{
			specs.Mount{
				Source:      c.dir,
				Destination: "/verityroot",
				Type:        "bind",
				Options:     []string{"verity.roothash="},
			},
		},
	}

	specutils.LogSpec(spec)

	cid := fmt.Sprintf("runsc-%06d", rand.Int31n(1000000))

	// Networking is not necessary to run the verity measure tool.
	addNamespace(spec, specs.LinuxNamespace{Type: specs.NetworkNamespace})

	out, err := json.Marshal(spec)
	if err != nil {
		return Errorf("Error to marshal spec: %v", err)
	}
	tmpDir, err := ioutil.TempDir("", "runsc-verity-prepare")
	if err != nil {
		return Errorf("Error to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	log.Infof("Changing configuration RootDir to %q", tmpDir)
	conf.RootDir = tmpDir

	cfgPath := filepath.Join(tmpDir, "config.json")
	if err := ioutil.WriteFile(cfgPath, out, 0755); err != nil {
		return Errorf("Error write spec: %v", err)
	}

	containerArgs := container.Args{
		ID:        cid,
		Spec:      spec,
		BundleDir: tmpDir,
		Attached:  true,
	}
	ct, err := container.New(conf, containerArgs)
	if err != nil {
		return Errorf("creating container: %v", err)
	}
	defer ct.Destroy()

	if err := ct.Start(conf); err != nil {
		return Errorf("starting container: %v", err)
	}

	// Forward signals to init in the container. Thus if we get SIGINT from
	// ^C, the container gracefully exit, and we can clean up.
	//
	// N.B. There is a still a window before this where a signal may kill
	// this process, skipping cleanup.
	stopForwarding := ct.ForwardSignals(0 /* pid */, false /* fgProcess */)
	defer stopForwarding()

	ws, err := ct.Wait()
	if err != nil {
		return Errorf("waiting for container: %v", err)
	}

	*waitStatus = ws
	return subcommands.ExitSuccess
}
