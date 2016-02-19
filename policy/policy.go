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
	"fmt"
	"strings"

	"github.com/gambol99/kube-cover/utils"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
)

// Matches checks to see if the context matches the policy filter
func (r PodSecurityPolicy) Matches(cx *PolicyContext) bool {
	// check for wild cards
	if found := utils.ContainedIn("*", r.Namespaces); found {
		return true
	}
	if found := utils.ContainedIn(cx.Namespace, r.Namespaces); found {
		return true
	}

	return false
}

// Conflicts checks if the pod spec violates the security specification
func (r PodSecurityPolicySpec) Conflicts(pod *api.PodSpec) error {
	// check for host pid
	if !r.HostPID && pod.HostPID {
		return fmt.Errorf("host pid")
	}
	// check for host ipc
	if !r.HostIPC && pod.HostIPC {
		return fmt.Errorf("host ipc")
	}
	if !r.HostNetwork && pod.HostNetwork {
		return fmt.Errorf("host network")
	}

	// check the volumes
	if r.Volumes != nil && len(pod.Volumes) > 0 {
		if err := r.Volumes.Conflicts(pod.Volumes); err != nil {
			return err
		}
	}

	// step: check the images
	if r.Images != nil {
		for _, c := range pod.Containers {
			if err := r.Images.Conflicts(c.Image); err != nil {
				return err
			}
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
func hasCapability(cap api.Capability, caps []*api.Capability) bool {
	for _, c := range caps {
		if cap == *c {
			return true
		}
	}

	return false
}

// Conflicts checks it does not violate the image policy
func (r ImageSecurityPolicy) Conflicts(image string) error {
	glog.V(20).Infof("checking image: %s, matchers: %d", image, len(r.matches))

	// step: iterate the regexes and find any matches
	for matcher, permitted := range r.matches {
		glog.V(20).Infof("checking image: %s against regexp: %s", image, matcher.String())
		if matched := matcher.MatchString(image); matched {
			if permitted {
				return nil
			}
			return fmt.Errorf("image: %s explicitly denied by policy", image)
		}
	}
	glog.V(20).Infof("permitted: %d, denied: %d", len(r.Permitted), len(r.Denied))

	if len(r.Permitted) <= 0 && len(r.Denied) <= 0 {
		return nil
	}

	return fmt.Errorf("image: %s denied by policy", image)
}

// Conflicts validates the pod volumes does not violate the security policy
func (r VolumeSecurityPolicy) Conflicts(volumes []api.Volume) error {
	if len(volumes) <= 0 {
		return nil
	}
	// step: validate each of the volumes
	for _, volume := range volumes {
		glog.V(20).Infof("checking volume %s", volume.Name)
		if !r.HostPath && volume.HostPath != nil {
			return fmt.Errorf("hostpath volume, %s not permitted", volume.Name)
		}
		if r.HostPath && len(r.HostPathAllowed) > 0 && volume.HostPath != nil {
			passed := false
			for _, path := range r.HostPathAllowed {
				if strings.Contains(volume.HostPath.Path, "..") {
					passed = false
					break
				}
				if strings.HasPrefix(volume.HostPath.Path, path) {
					passed = true
					break
				}
			}
			// did any of the path start with the paths allowed?
			if !passed {
				return fmt.Errorf("host path %s", volume.HostPath.Path)
			}
		}
		if !r.AWSElasticBlockStore && volume.AWSElasticBlockStore != nil {
			return fmt.Errorf("aws ebs volume: %s", volume.Name)
		}
		if !r.CephFS && volume.CephFS != nil {
			return fmt.Errorf("cephfs volume: %s", volume.Name)
		}
		if !r.Cinder && volume.Cinder != nil {
			return fmt.Errorf("cinder volume: %s", volume.Name)
		}
		if !r.DownwardAPI && volume.DownwardAPI != nil {
			return fmt.Errorf("downwardapi volume: %s", volume.Name)
		}
		if !r.EmptyDir && volume.EmptyDir != nil {
			return fmt.Errorf("emptydir volume: %s", volume.Name)
		}
		if !r.FC && volume.FC != nil {
			return fmt.Errorf("fc volume: %s", volume.Name)
		}
		if !r.GCEPersistentDisk && volume.GCEPersistentDisk != nil {
			return fmt.Errorf("gce volume: %s", volume.Name)
		}
		if !r.GitRepo && volume.GitRepo != nil {
			return fmt.Errorf("gitrepo volume: %s", volume.Name)
		}
		if !r.Glusterfs && volume.Glusterfs != nil {
			return fmt.Errorf("glusterfs volume: %s", volume.Name)
		}
		if !r.ISCSI && volume.ISCSI != nil {
			return fmt.Errorf("isci volume: %s", volume.Name)
		}
		if !r.NFS && volume.NFS != nil {
			return fmt.Errorf("nfs volume: %s", volume.Name)
		}
		if !r.PersistentVolumeClaim && volume.PersistentVolumeClaim != nil {
			return fmt.Errorf("persistent volume: %s", volume.Name)
		}
		if !r.RBD && volume.RBD != nil {
			return fmt.Errorf("rbd volume: %s", volume.Name)
		}
		if !r.Secret && volume.Secret != nil {
			return fmt.Errorf("secret volume: %s", volume.Name)
		}
	}

	return nil
}

// Conflicts validate the runas pod specification does not violate the security policies
func (r RunAsUserStrategyOptions) Conflicts(runas *api.SecurityContext) error {
	return nil
}
