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
	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	"strings"
)

func (r VolumeSecurityPolicy) Conflicts(volumes []api.Volume) error {
	if len(volumes) <= 0 {
		return nil
	}
	// step: validate each of the volumes
	for _, volume := range volumes {
		glog.V(20).Infof("checking volume %s", volume.Name)
		if !r.HostPath && volume.HostPath != nil {
			return fmt.Errorf("hostpath volume, %s", volume.Name)
		}
		if r.HostPath && len(r.HostPathAllowed) > 0 && volume.HostPath != nil {
			passed := false
			for _, path := range r.HostPathAllowed {
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
			return fmt.Errorf("cephfs volume: %s", volume.Name)
		}
		if !r.DownwardAPI && volume.DownwardAPI != nil {
			return fmt.Errorf("cephfs volume: %s", volume.Name)
		}
		if !r.EmptyDir && volume.EmptyDir != nil {
			return fmt.Errorf("cephfs volume: %s", volume.Name)
		}
		if !r.FC && volume.FC != nil {
			return fmt.Errorf("cephfs volume: %s", volume.Name)
		}
		if !r.GCEPersistentDisk && volume.GCEPersistentDisk != nil {
			return fmt.Errorf("cephfs volume: %s", volume.Name)
		}
		if !r.GitRepo && volume.GitRepo != nil {
			return fmt.Errorf("cephfs volume: %s", volume.Name)
		}
		if !r.Glusterfs && volume.Glusterfs != nil {
			return fmt.Errorf("cephfs volume: %s", volume.Name)
		}
		if !r.ISCSI && volume.ISCSI != nil {
			return fmt.Errorf("isci volume: %s", volume.Name)
		}
		if !r.NFS && volume.NFS != nil {
			return fmt.Errorf("cfs volume: %s", volume.Name)
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
