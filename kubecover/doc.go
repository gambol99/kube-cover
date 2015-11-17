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
	"net/http/httputil"
	"net/url"

	"github.com/gambol99/kube-cover/policy"

	"github.com/gin-gonic/gin"
)

const (
	requestUnauthorized = "unauthorized"
	headerConnection    = "Connection"
	headerUpgrade       = "Upgrade"
)

// KubeCover is the proxy service
type KubeCover struct {
	// the gin engine
	engine *gin.Engine
	// the reverse proxy
	proxy *httputil.ReverseProxy
	// the upstream url
	upstream *url.URL
	// the upstream endpoint
	upstreamEndpoint string
	// the policy enforcer
	acl policy.Controller
}
