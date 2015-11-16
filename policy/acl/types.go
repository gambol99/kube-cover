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
	"time"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
)

// PolicyContext provides contextual information for authorization
type PolicyContext struct {
	// the time
	Time time.Time
	// the namespace
	Namespace string
	// the user
	User string
	// the group the user is in
	Groups []string
}

// PodSecurityPolicy governs the ability to make requests that affect the SecurityContext
// that will be applied to a pod and container.
type PodSecurityPolicy struct {
	unversioned.TypeMeta `json:",inline"`

	// -- To whom this policy is applied --
	// The users who have permissions to use this policy
	Users []string `json:"users,omitempty"`
	// The groups that have permission to use this policy
	Groups []string `json:"groups,omitempty"`
	// The namespace the policy is applied to
	Namespaces []string `json:"namespaces,omitempty"`

	// Spec defines the policy enforced.
	Spec PodSecurityPolicySpec `json:"spec,omitempty"`
}

// PodSecurityPolicySpec defines the policy enforced.
type PodSecurityPolicySpec struct {
	// Privileged determines if a pod can request to be run as privileged.
	Privileged bool `json:"privileged,omitempty"`
	// Capabilities is a list of capabilities that can be added.
	Capabilities []api.Capability `json:"capabilities,omitempty"`
	// Volumes allows and disallows the use of different types of volume plugins.
	Volumes VolumeSecurityPolicy `json:"volumes,omitempty"`
	// HostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
	HostNetwork bool `json:"hostNetwork,omitempty"`
	// HostPorts determines which host port ranges are allowed to be exposed.
	HostPorts []HostPortRange `json:"hostPorts,omitempty"`
	// HostPID determines if the policy allows the use of HostPID in the pod spec.
	HostPID bool `json:"hostPID,omitempty"`
	// HostIPC determines if the policy allows the use of HostIPC in the pod spec.
	HostIPC bool `json:"hostIPC,omitempty"`
	// SELinuxContext is the strategy that will dictate the allowable labels that may be set.
	SELinuxContext SELinuxContextStrategyOptions `json:"seLinuxContext,omitempty"`
	// RunAsUser is the strategy that will dictate the allowable RunAsUser values that may be set.
	RunAsUser RunAsUserStrategyOptions `json:"runAsUser,omitempty"`
}

// HostPortRange defines a range of host ports that will be enabled by a policy
// for pods to use.  It requires both the start and end to be defined.
type HostPortRange struct {
	// Start is the beginning of the port range which will be allowed.
	Start int `json:"start"`
	// End is the end of the port range which will be allowed.
	End int `json:"end"`
}

// VolumeSecurityPolicy allows and disallows the use of different types of volume plugins.
type VolumeSecurityPolicy struct {
	// HostPath allows or disallows the use of the HostPath volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/volumes.md#hostpath
	HostPath bool `json:"hostPath,omitempty"`
	// HostPathAllowed allow the collection of host paths through
	HostPathAllowed []string `json:"hostPathAllowed,omitempty"`
	// EmptyDir allows or disallows the use of the EmptyDir volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/volumes.md#emptydir
	EmptyDir bool `json:"emptyDir,omitempty"`
	// GCEPersistentDisk allows or disallows the use of the GCEPersistentDisk volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/volumes.md#gcepersistentdisk
	GCEPersistentDisk bool `json:"gcePersistentDisk,omitempty"`
	// AWSElasticBlockStore allows or disallows the use of the AWSElasticBlockStore volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/volumes.md#awselasticblockstore
	AWSElasticBlockStore bool `json:"awsElasticBlockStore,omitempty"`
	// GitRepo allows or disallows the use of the GitRepo volume plugin.
	GitRepo bool `json:"gitRepo,omitempty"`
	// Secret allows or disallows the use of the Secret volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/volumes.md#secrets
	Secret bool `json:"secret,omitempty"`
	// NFS allows or disallows the use of the NFS volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/volumes.md#nfs
	NFS bool `json:"nfs,omitempty"`
	// ISCSI allows or disallows the use of the ISCSI volume plugin.
	// More info: http://releases.k8s.io/HEAD/examples/iscsi/README.md
	ISCSI bool `json:"iscsi,omitempty"`
	// Glusterfs allows or disallows the use of the Glusterfs volume plugin.
	// More info: http://releases.k8s.io/HEAD/examples/glusterfs/README.md
	Glusterfs bool `json:"glusterfs,omitempty"`
	// PersistentVolumeClaim allows or disallows the use of the PersistentVolumeClaim volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/persistent-volumes.md#persistentvolumeclaims
	PersistentVolumeClaim bool `json:"persistentVolumeClaim,omitempty"`
	// RBD allows or disallows the use of the RBD volume plugin.
	// More info: http://releases.k8s.io/HEAD/examples/rbd/README.md
	RBD bool `json:"rbd,omitempty"`
	// Cinder allows or disallows the use of the Cinder volume plugin.
	// More info: http://releases.k8s.io/HEAD/examples/mysql-cinder-pd/README.md
	Cinder bool `json:"cinder,omitempty"`
	// CephFS allows or disallows the use of the CephFS volume plugin.
	CephFS bool `json:"cephfs,omitempty"`
	// DownwardAPI allows or disallows the use of the DownwardAPI volume plugin.
	DownwardAPI bool `json:"downwardAPI,omitempty"`
	// FC allows or disallows the use of the FC volume plugin.
	FC bool `json:"fc,omitempty"`
}

// SELinuxContextStrategyOptions defines the strategy type and any options used to create the strategy.
type SELinuxContextStrategyOptions struct {
	// Type is the strategy that will dictate the allowable labels that may be set.
	Type SELinuxContextStrategy `json:"type"`
	// seLinuxOptions required to run as; required for MustRunAs
	// More info: http://releases.k8s.io/HEAD/docs/design/security_context.md#security-context
	SELinuxOptions *api.SELinuxOptions `json:"seLinuxOptions,omitempty"`
}

// SELinuxContextStrategyType denotes strategy types for generating SELinux options for a
// SecurityContext.
type SELinuxContextStrategy string

const (
	// container must have SELinux labels of X applied.
	SELinuxStrategyMustRunAs SELinuxContextStrategy = "MustRunAs"
	// container may make requests for any SELinux context labels.
	SELinuxStrategyRunAsAny SELinuxContextStrategy = "RunAsAny"
)

// RunAsUserStrategyOptions defines the strategy type and any options used to create the strategy.
type RunAsUserStrategyOptions struct {
	// Type is the strategy that will dictate the allowable RunAsUser values that may be set.
	Type RunAsUserStrategy `json:"type"`
	// UID is the user id that containers must run as.  Required for the MustRunAs strategy if not using
	// a strategy that supports pre-allocated uids.
	UID *int64 `json:"uid,omitempty"`
	// UIDRangeMin defines the min value for a strategy that allocates by a range based strategy.
	UIDRangeMin *int64 `json:"uidRangeMin,omitempty"`
	// UIDRangeMax defines the max value for a strategy that allocates by a range based strategy.
	UIDRangeMax *int64 `json:"uidRangeMax,omitempty"`
}

// RunAsUserStrategyType denotes strategy types for generating RunAsUser values for a
// SecurityContext.
type RunAsUserStrategy string

const (
	// container must run as a particular uid.
	RunAsUserStrategyMustRunAs RunAsUserStrategy = "MustRunAs"
	// container must run as a particular uid.
	RunAsUserStrategyMustRunAsRange RunAsUserStrategy = "MustRunAsRange"
	// container must run as a non-root uid
	RunAsUserStrategyMustRunAsNonRoot RunAsUserStrategy = "MustRunAsNonRoot"
	// container may make requests for any uid.
	RunAsUserStrategyRunAsAny RunAsUserStrategy = "RunAsAny"
)

// PodSecurityPolicyList is a list of PodSecurityPolicy objects.
type PodSecurityPolicyList struct {
	unversioned.TypeMeta `json:",inline"`
	unversioned.ListMeta `json:"metadata,omitempty"`

	Items []PodSecurityPolicy `json:"items"`
}
