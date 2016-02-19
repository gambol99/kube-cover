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
	"fmt"
	"net/http/httputil"
	"net/url"

	"github.com/gambol99/kube-cover/policy"

	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
)

// NewCover creates a new kube cover service
func NewCover(upstream, policyPath string) (*KubeCover, error) {
	// step: parse and validate the upstreams
	location, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstrem url, %s", err)
	}

	service := new(KubeCover)
	service.upstream = location

	glog.Infof("kubernetes api: %s", service.upstream.String())

	// step: create the policy controller
	acl, err := policy.NewController(policyPath)
	if err != nil {
		return nil, err
	}
	service.acl = acl

	// step: create the gin router
	router := gin.Default()
	router.Use(service.proxyHandler())

	// step: handle operations related to replication controllers]
	replicationEndpoint := "/api/v1/namespaces/:namespace/replicationcontrollers"
	replicationUpdateEndpoint := "/api/v1/namespaces/:namespace/replicationcontrollers/:name"
	router.POST(replicationEndpoint, service.handleReplicationController)
	router.PATCH(replicationUpdateEndpoint, service.handleReplicationController)
	router.PUT(replicationUpdateEndpoint, service.handleReplicationController)

	// step: handle the post operations
	podEndpoint := "/api/v1/namespaces/:namespace/pods"
	podUpdate := "/api/v1/namespaces/:namespace/pods/:name"
	router.POST(podEndpoint, service.handlePods)
	router.PATCH(podUpdate, service.handlePods)
	router.PUT(podUpdate, service.handlePods)

	service.engine = router

	// step: create and setup the reverse proxy
	service.proxy = httputil.NewSingleHostReverseProxy(service.upstream)
	service.proxy.Transport = buildTransport()

	return service, nil
}

// decodeInput decodes the json payload
func (r *KubeCover) decodeInput(req *http.Request, data interface{}) (string, error) {
	// step: read in the content payload
	content, err := ioutil.ReadAll(req.Body)
	if err != nil {
		glog.Errorf("unable to read in the content, error: %s", err)
		return "", err
	}
	defer func() {
		// we need to set the content back
		req.Body = ioutil.NopCloser(bytes.NewReader(content))
	}()

	rdr := strings.NewReader(string(content))

	// step: decode the json
	err = json.NewDecoder(rdr).Decode(data)
	if err != nil {
		glog.Errorf("unable to decode the request body, error: %s", err)
		return "", err
	}

	return string(content), nil
}

// Run start the gin engine and begins serving content
func (r *KubeCover) Run(address, certFile, privateFile string) error {
	if err := r.engine.RunTLS(address, certFile, privateFile); err != nil {
		return err
	}

	return nil
}

// tryUpdateConnection attempt to upgrade the connection to a http pdy stream
func (r *KubeCover) tryUpdateConnection(cx *gin.Context) error {
	// step: dial the kubernetes endpoint
	tlsConn, err := tryDialEndpoint(r.upstream)
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	// step: we need to hijack the underlining client connection
	clientConn, _, err := cx.Writer.(http.Hijacker).Hijack()
	if err != nil {

	}
	defer clientConn.Close()

	// step: write the request to upstream
	if err = cx.Request.Write(tlsConn); err != nil {
		return err
	}

	// step: copy the date between client and upstream endpoint
	var wg sync.WaitGroup
	wg.Add(2)
	go transferBytes(tlsConn, clientConn, &wg)
	go transferBytes(clientConn, tlsConn, &wg)
	wg.Wait()

	glog.V(10).Infof("closing the http stream from upstream and client")

	return nil
}
