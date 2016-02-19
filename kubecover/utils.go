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

package kubecover

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
)

// buildTransport creates and returns the default transport
func buildTransport() *http.Transport {
	return &http.Transport{
		//Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

// printRequest display the request
func printRequest(req *http.Request) string {
	content, err := httputil.DumpRequest(req, true)
	if err != nil {
		return ""
	}

	return string(content)
}

// isUpgradedConnection checks to see if the request is requesting
func isUpgradedConnection(req *http.Request) bool {
	if req.Header.Get(headerUpgrade) != "" {
		return true
	}

	return false
}

// tryDialEndpoint dials the upstream endpoint via plain
func tryDialEndpoint(location *url.URL) (net.Conn, error) {
	glog.V(10).Infof("attempting to dial: %s", location.String())
	// get the dial address
	dialAddr := dialAddress(location)

	switch location.Scheme {
	case "http":
		glog.V(10).Infof("connecting the http endpoint: %s", dialAddr)
		conn, err := net.Dial("tcp", dialAddr)
		if err != nil {
			return nil, err
		}
		return conn, nil
	default:
		glog.V(10).Infof("connecting to tls endpoint: %s", dialAddr)
		// step: construct and dial a tls endpoint
		conn, err := tls.Dial("tcp", dialAddr, &tls.Config{
			Rand:               rand.Reader,
			InsecureSkipVerify: true,
		})

		if err != nil {
			return nil, err
		}

		return conn, nil
	}
}

// dialAddress extracts the dial address from the url
func dialAddress(location *url.URL) string {
	items := strings.Split(location.Host, ":")
	if len(items) != 2 {
		switch location.Scheme {
		case "http":
			return location.Host + ":80"
		default:
			return location.Host + ":443"
		}
	}

	return location.Host
}

// transferBytes transfers bytes between the sink and source
func transferBytes(src io.Reader, dest io.Writer, wg *sync.WaitGroup) (int64, error) {
	defer wg.Done()
	copied, err := io.Copy(dest, src)
	if err != nil {
		return copied, err
	}

	return copied, nil
}
