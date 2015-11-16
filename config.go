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
)

var config struct {
	// the listening addrress
	bindInterface string
	// the path to the cerificate
	certificateFile string
	// the path the private ket
	privateKeyFile string
	// the upstream k8s url
	upstreamURL string
	// the path the policy file
	policyFile string
}

func init() {
	flag.StringVar(&config.certificateFile, "tls-cert", "", "the path to the tls cerfiicate for the service to use")
	flag.StringVar(&config.privateKeyFile, "tls-key", "", "the path to the tls private key for the service")
	flag.StringVar(&config.upstreamURL, "url", "https://127.0.0.1:6443", "the url for the kubernetes upstream api service, must be https")
	flag.StringVar(&config.policyFile, "policy-file", "", "the path to the policy file container authorization security policies")
	flag.StringVar(&config.bindInterface, "bind", ":6444", "the interface and port for the service to listen on")
}

// parseConfig validate the command line options
func parseConfig() error {
	flag.Parse()

	if config.certificateFile == "" {
		return fmt.Errorf("you have not specified a certificate to use")
	}
	if config.privateKeyFile == "" {
		return fmt.Errorf("you have not specified a private key to use")
	}
	if config.upstreamURL == "" {
		return fmt.Errorf("you have not specified the upstream kubernetes api url")
	}
	if config.policyFile == "" {
		return fmt.Errorf("you have not specified the policy file")
	}

	return nil
}
