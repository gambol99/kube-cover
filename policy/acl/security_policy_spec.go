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

package acl

import (
	"fmt"

	"k8s.io/kubernetes/pkg/api"
)

// Conflicts checks if the pod spec violates the security specification
func (r PodSecurityPolicySpec) Conflicts(pod *api.PodSpec) error {
	// check for host pid
	if !r.HostPID && pod.HostPID {
		return fmt.Errorf("host pid")
	}
	// check for host ipc
	if !r.HostIPC && pod.HostIPC {
		return fmt.Errorf("host ipd")
	}
	if !r.HostNetwork && pod.HostNetwork {
		return fmt.Errorf("host network")
	}

	// check the volumes
	if len(pod.Volumes) > 0 {
		if err := r.Volumes.Conflicts(pod.Volumes); err != nil {
			return err
		}
	}

	// step: iterate each of the container in the pod and verify
	for _, c := range pod.Containers {
		// check privileged mode
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil {
				if c.SecurityContext.Privileged != nil {
					if !r.Privileged && *c.SecurityContext.Privileged {
						return fmt.Errorf("privileged mode")
					}
				}
			}

			if c.SecurityContext.Capabilities != nil {
				for _, cp := range c.SecurityContext.Capabilities.Add {
					if !hasCapability(cp, r.Capabilities) {
						return fmt.Errorf("capability %s", cp)
					}
				}
			}

			// check the host network
			if err := r.RunAsUser.Conflicts(c.SecurityContext); err != nil {
				return err
			}
		}

		// check the host ports
		hostPorts := len(r.HostPorts)
		if hostPorts <= 0 {
			for _, port := range c.Ports {
				if port.HostPort > 0 {
					return fmt.Errorf("host port %d", port.HostPort)
				}
			}
		} else {
			for _, rn := range r.HostPorts {
				for _, port := range c.Ports {
					if port.HostPort < rn.Start || port.HostPort > rn.End {
						return fmt.Errorf("host port %d", port.HostPort)
					}
				}
			}
		}
	}

	return nil
}

// hasCapability checks if the capability is in the list of capabilities
func hasCapability(cap api.Capability, caps []api.Capability) bool {
	for _, c := range caps {
		if cap == c {
			return true
		}
	}

	return false
}
