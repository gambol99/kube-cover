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

package policy

import (
	"sync"

	"github.com/gambol99/kube-cover/policy/acl"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
)

type policyEnforcer struct {
	// the file container the policies
	policyFile string
	// a list of policies
	policies *acl.PodSecurityPolicyList
	// a lock to guard updating the list
	policyLock sync.RWMutex
}

// NewController create a new policy controller, reading in the policies from the file
func NewController(path string) (Controller, error) {
	// step: read in the policy file
	glog.Infof("loading the policies file: %s", path)
	policies, err := parsePolicyFile(path)
	if err != nil {
		return nil, err
	}
	glog.Infof("found %d polices in the file", len(policies.Items))

	return &policyEnforcer{
		policyFile: path,
		policies:   policies,
	}, nil
}

// Authorized validates the pod and parameters are valid
func (r *policyEnforcer) Authorized(cx *acl.PolicyContext, pod *api.PodSpec) error {
	glog.Infof("validating the pod spec, namespace: %s", cx.Namespace)
	for _, p := range r.policies.Items {
		// step: check if the policy matches
		if match := p.Matches(cx); !match {
			continue
		}
		// step: check for conflicts
		if err := p.Spec.Conflicts(pod); err != nil {
			return err
		}
		break
	}

	return nil
}
