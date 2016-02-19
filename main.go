/*

Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gambol99/kube-cover/kubecover"

	"github.com/golang/glog"
)

func main() {
	if err := parseConfig(); err != nil {
		printUsage(err.Error())
	}

	glog.Infof("initializing kube cover service, version: %s", version)

	// step: create the kube cover service
	cover, err := kubecover.NewCover(config.upstreamURL, config.policyFile)
	if err != nil {
		printUsage(err.Error())
	}

	// step: start handling requests
	if err := cover.Run(config.bindInterface, config.certificateFile, config.privateKeyFile); err != nil {
		printUsage(err.Error())
	}
}

// printUsage prints the usage menu
func printUsage(message string) {
	flag.PrintDefaults()
	if message != "" {
		fmt.Fprintf(os.Stderr, "[error] %s", message)
		os.Exit(1)
	}
	os.Exit(1)
}
