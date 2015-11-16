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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
)

// proxyHandler proxies the request on to the upstream endpoint
func (r *KubeCover) proxyHandler(cx *gin.Context) {
	// step: has the request been flagged as unauthorized?
	_, authorized := cx.Get(REQUEST_UNAUTHORIZED)
	if authorized {
		return
	}

	// step: does the connection need upgrading?
	if cx.Request.Header.Get("Upgrade") != "" {
		if err := r.hijackRequest(cx); err != nil {
			glog.Errorf("unable to upgrade the connetcion, %s", err)
		}
		return
	}

	// step: pass into the reverse proxy
	r.proxy.ServeHTTP(cx.Writer, cx.Request)
}

func (r *KubeCover) hijackRequest(cx *gin.Context) error {
	cx.AbortWithStatus(http.StatusInternalServerError)
	// step: attempt to hijack the request
	hijack, ok := cx.Writer.(http.Hijacker)
	if !ok {
		return fmt.Errorf("unable to hijack the reqiest, hijacking not supported")
	}

	// step: we grab the underlining connection
	clientConn, _, err := hijack.Hijack()
	if err != nil {
		return fmt.Errorf("unable to hijack the underlining connection, %s", err)
	}

	// step: a dial connection and create a connection to the sink
	tcpConn, err := net.Dial("tcp", r.upstreamEndpoint)
	if err != nil {
		return fmt.Errorf("unable to dial the upstream endpoint, %s", err)
	}
	cf := &tls.Config{
		Rand:               rand.Reader,
		InsecureSkipVerify: true,
	}
	ssl := tls.Client(tcpConn, cf)

	url := fmt.Sprintf("%s://%s%s", r.upstream.Scheme, r.upstream.Host, cx.Request.URL.String())

	req, err := http.NewRequest(cx.Request.Method, url, cx.Request.Body)
	if err != nil {
		return fmt.Errorf("unable to create the request, %s", err)
	}

	req.Header = cx.Request.Header

	server := httputil.NewClientConn(ssl, nil)
	if err != nil {
		return fmt.Errorf("unable to write the request upstream, %s", err)
	}
	_, err = server.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform request, %s", err)
	}
	// step: hijack the response
	serverConn, _ := server.Hijack()

	var wg sync.WaitGroup
	wg.Add(2)
	go transferBytes(clientConn, serverConn, &wg)
	go transferBytes(serverConn, clientConn, &wg)
	wg.Wait()

	return nil
}

func transferBytes(src io.Reader, dest io.Writer, wg *sync.WaitGroup) (int64, error) {
	defer wg.Done()
	glog.V(10).Info("coping data")
	copied, err := io.Copy(dest, src)
	if err != nil {
		glog.Errorf("unable to transfer byte, error: %s", err)
		return copied, err
	}
	src.(net.Conn).Close()
	dest.(net.Conn).Close()
	return copied, nil
}
