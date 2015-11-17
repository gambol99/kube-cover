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
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
)

// proxyHandler proxies the request on to the upstream endpoint
func (r *KubeCover) proxyHandler(cx *gin.Context) {
	// step: has the request been flagged as unauthorized?
	_, authorized := cx.Get(Request_Unauthorized)
	if authorized {
		return
	}

	// step: is this connection upgrading?
	if isUpgradedConnection(cx.Request) {
		glog.V(10).Infof("upgrading the connnection to %s", cx.Request.Header.Get("Upgrade"))
		if err := r.tryUpdateConnection(cx); err != nil {
			glog.Errorf("unable to upgrade the connection, %s", err)
			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		cx.Abort()

		return
	}

	glog.V(10).Infof("proxing the request")
	// step: pass through to the reverse proxy
	r.proxy.ServeHTTP(cx.Writer, cx.Request)
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
