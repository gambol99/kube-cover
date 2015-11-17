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
	"net/http"

	"github.com/gambol99/kube-cover/policy/acl"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
)

// handleReplicationController handles and filter the replication controller operations
func (r *KubeCover) handleReplicationController(cx *gin.Context) {
	context, err := r.deriveContext(cx)
	if err != nil {
		cx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// step: decode the controller
	controller := new(api.ReplicationController)
	content, err := r.decodeInput(cx.Request, controller)
	if err != nil {
		cx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	glog.V(10).Infof("authorizating replication controller, namespace: %s, name: %s", context.Namespace,
		controller.Name)

	// step: validate against the policy
	if err := r.acl.Authorized(context, &controller.Spec.Template.Spec); err != nil {
		r.unauthorizedRequest(cx, content, err.Error())
		return
	}

	glog.V(10).Infof("continuing the chain, is aborted: %t", cx.IsAborted())
}

// handlePods handles the changes made to pods
func (r *KubeCover) handlePods(cx *gin.Context) {
	context, err := r.deriveContext(cx)
	if err != nil {
		glog.Errorf("unable to retrieve the request content")
		cx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// step: decode the pod spec
	pod := new(api.PodSpec)
	content, err := r.decodeInput(cx.Request, pod)
	if err != nil {
		glog.Errorf("unable to decode the request body, error: %s", err)
		cx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// step: validate against the policy
	if err := r.acl.Authorized(context, pod); err != nil {
		r.unauthorizedRequest(cx, content, err.Error())
		return
	}
}

// unauthorizedRequest sends back a failure to the client
func (r KubeCover) unauthorizedRequest(cx *gin.Context, spec, message string) {
	glog.Errorf("unauthorized request from: (%s), failure: %s violation", cx.Request.RemoteAddr, message)
	glog.Errorf("failing specification: %s", spec)

	// step: inject the header
	cx.Set(requestUnauthorized, true)

	cx.JSON(http.StatusNotAcceptable, gin.H{
		"status":  "Failure",
		"message": "security policy violation, reason: " + message,
	})
}

// deriveContext gather's additional content for the authorization
func (r *KubeCover) deriveContext(cx *gin.Context) (*acl.PolicyContext, error) {
	namespace := cx.Param("namespace")
	if namespace == "" {
		return nil, fmt.Errorf("the request has not namespace associated")
	}

	return &acl.PolicyContext{
		Namespace: namespace,
	}, nil
}
