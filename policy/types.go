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
	"regexp"
	"time"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
)

// RunAsUserStrategy denotes strategy types for generating RunAsUser values for a
// SecurityContext.
type RunAsUserStrategy string

const (
	// SELinuxStrategyMustRunAs container must have SELinux labels of X applied.
	SELinuxStrategyMustRunAs SELinuxContextStrategy = "MustRunAs"
	// SELinuxStrategyRunAsAny container may make requests for any SELinux context labels.
	SELinuxStrategyRunAsAny SELinuxContextStrategy = "RunAsAny"
	// RunAsUserStrategyMustRunAs container must run as a particular uid.
	RunAsUserStrategyMustRunAs RunAsUserStrategy = "MustRunAs"
	// RunAsUserStrategyMustRunAsRange container must run as a particular uid.
	RunAsUserStrategyMustRunAsRange RunAsUserStrategy = "MustRunAsRange"
	// RunAsUserStrategyMustRunAsNonRoot container must run as a non-root uid
	RunAsUserStrategyMustRunAsNonRoot RunAsUserStrategy = "MustRunAsNonRoot"
	// RunAsUserStrategyRunAsAny container may make requests for any uid.
	RunAsUserStrategyRunAsAny RunAsUserStrategy = "RunAsAny"
)

// PolicyContext provides contextual information for authorization
type PolicyContext struct {
	// Time is the time
	Time time.Time
	// Namespace is the namespace
	Namespace string
}

// PodSecurityPolicy governs the ability to make requests that affect the SecurityContext
// that will be applied to a pod and container.
type PodSecurityPolicy struct {
	unversioned.TypeMeta `json:",inline"`
	// Namespaces is namespaces the policy is applied to
	Namespaces []string `json:"namespaces" yaml:"namespaces"`
	// Spec defines the policy enforced.
	Spec *PodSecurityPolicySpec `json:"spec" yaml:"spec"`
}

// PodSecurityPolicySpec defines the policy enforced.
type PodSecurityPolicySpec struct {
	// Privileged determines if a pod can request to be run as privileged.
	Privileged bool `json:"privileged" yaml:"privileged"`
	// Capabilities is a list of capabilities that can be added.
	Capabilities []*api.Capability `json:"capabilities" yaml:"capabilities"`
	// Volumes allows and disallows the use of different types of volume plugins.
	Volumes *VolumeSecurityPolicy `json:"volumes" yaml:"volumes"`
	// Images allow or disallows container images
	Images *ImageSecurityPolicy `json:"images" yaml:"images"`
	// HostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
	HostNetwork bool `json:"hostNetwork" yaml:"hostnetwork"`
	// HostPorts determines which host port ranges are allowed to be exposed.
	HostPorts []*HostPortRange `json:"hostPorts" yaml:"hostports"`
	// HostPID determines if the policy allows the use of HostPID in the pod spec.
	HostPID bool `json:"hostPID" yaml:"hostpids"`
	// HostIPC determines if the policy allows the use of HostIPC in the pod spec.
	HostIPC bool `json:"hostIPC" yaml:"hostipc"`
	// SELinuxContext is the strategy that will dictate the allowable labels that may be set.
	SELinuxContext SELinuxContextStrategyOptions `json:"seLinuxContext" yaml:"selinuxcontext"`
	// RunAsUser is the strategy that will dictate the allowable RunAsUser values that may be set.
	RunAsUser RunAsUserStrategyOptions `json:"runAsUser" yaml:"runasuser"`
}

// HostPortRange defines a range of host ports that will be enabled by a policy
// for pods to use.  It requires both the start and end to be defined.
type HostPortRange struct {
	// Start is the beginning of the port range which will be allowed.
	Start int `json:"start" yaml:"start"`
	// End is the end of the port range which will be allowed.
	End int `json:"end" yaml:"end"`
}

// ImageSecurityPolicy specifies the image security policy
type ImageSecurityPolicy struct {
	// Permitted is series of regexes which are applied to the container image
	Permitted []string `json:"permitted" yaml:"permitted"`
	// Denied is a series of regexes which are denied
	Denied []string `json:"denied" yaml:"denied"`
	// the above converted to regexes
	matches map[*regexp.Regexp]bool
}

// VolumeSecurityPolicy allows and disallows the use of different types of volume plugins.
type VolumeSecurityPolicy struct {
	// HostPath allows or disallows the use of the HostPath volume plugin.
	HostPath bool `json:"hostPath" yaml:"hostpath"`
	// HostPathAllowed allow the collection of host paths through
	HostPathAllowed []string `json:"hostPathAllowed" yaml:"hostpathallowed"`
	// EmptyDir allows or disallows the use of the EmptyDir volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/volumes.md#emptydir
	EmptyDir bool `json:"emptyDir" yaml:"emptyDir"`
	// GCEPersistentDisk allows or disallows the use of the GCEPersistentDisk volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/volumes.md#gcepersistentdisk
	GCEPersistentDisk bool `json:"gcePersistentDisk" yaml:"gcepersistentdisk"`
	// AWSElasticBlockStore allows or disallows the use of the AWSElasticBlockStore volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/volumes.md#awselasticblockstore
	AWSElasticBlockStore bool `json:"awsElasticBlockStore" yaml:"awselasticblockstore"`
	// GitRepo allows or disallows the use of the GitRepo volume plugin.
	GitRepo bool `json:"gitRepo" yaml:"gitrepo"`
	// Secret allows or disallows the use of the Secret volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/volumes.md#secrets
	Secret bool `json:"secret" yaml:"secret"`
	// NFS allows or disallows the use of the NFS volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/volumes.md#nfs
	NFS bool `json:"nfs" yaml:"nfs"`
	// ISCSI allows or disallows the use of the ISCSI volume plugin.
	// More info: http://releases.k8s.io/HEAD/examples/iscsi/README.md
	ISCSI bool `json:"iscsi" yaml:"iscsi"`
	// Glusterfs allows or disallows the use of the Glusterfs volume plugin.
	// More info: http://releases.k8s.io/HEAD/examples/glusterfs/README.md
	Glusterfs bool `json:"glusterfs" yaml:"glusterfs"`
	// PersistentVolumeClaim allows or disallows the use of the PersistentVolumeClaim volume plugin.
	// More info: http://releases.k8s.io/HEAD/docs/user-guide/persistent-volumes.md#persistentvolumeclaims
	PersistentVolumeClaim bool `json:"persistentVolumeClaim" yaml:"persistentvolumeclaim"`
	// RBD allows or disallows the use of the RBD volume plugin.
	// More info: http://releases.k8s.io/HEAD/examples/rbd/README.md
	RBD bool `json:"rbd" yaml:"rbd"`
	// Cinder allows or disallows the use of the Cinder volume plugin.
	// More info: http://releases.k8s.io/HEAD/examples/mysql-cinder-pd/README.md
	Cinder bool `json:"cinder" yaml:"cinder"`
	// CephFS allows or disallows the use of the CephFS volume plugin.
	CephFS bool `json:"cephfs" yaml:"cephfs"`
	// DownwardAPI allows or disallows the use of the DownwardAPI volume plugin.
	DownwardAPI bool `json:"downwardAPI" yaml:"downwardapi"`
	// FC allows or disallows the use of the FC volume plugin.
	FC bool `json:"fc" yaml:"fc"`
}

// SELinuxContextStrategyOptions defines the strategy type and any options used to create the strategy.
type SELinuxContextStrategyOptions struct {
	// Type is the strategy that will dictate the allowable labels that may be set.
	Type SELinuxContextStrategy `json:"type" yaml:"type"`
	// seLinuxOptions required to run as; required for MustRunAs
	// More info: http://releases.k8s.io/HEAD/docs/design/security_context.md#security-context
	SELinuxOptions *api.SELinuxOptions `json:"seLinuxOptions" yaml:"selinuxoptions"`
}

// SELinuxContextStrategy denotes strategy types for generating SELinux options for a
// SecurityContext.
type SELinuxContextStrategy string

// RunAsUserStrategyOptions defines the strategy type and any options used to create the strategy.
type RunAsUserStrategyOptions struct {
	// Type is the strategy that will dictate the allowable RunAsUser values that may be set.
	Type RunAsUserStrategy `json:"type" yaml:"type"`
	// UID is the user id that containers must run as.  Required for the MustRunAs strategy if not using
	// a strategy that supports pre-allocated uids.
	UID *int64 `json:"uid" yaml:"uid"`
	// UIDRangeMin defines the min value for a strategy that allocates by a range based strategy.
	UIDRangeMin *int64 `json:"uidRangeMin" yaml:"uidrangemin"`
	// UIDRangeMax defines the max value for a strategy that allocates by a range based strategy.
	UIDRangeMax *int64 `json:"uidRangeMax" yaml:"uidrangemax"`
}

// PodSecurityPolicyList is a list of PodSecurityPolicy objects.
type PodSecurityPolicyList struct {
	unversioned.TypeMeta `json:",inline"`
	unversioned.ListMeta `json:"metadata"`

	Items []*PodSecurityPolicy `json:"items" yaml:"items"`
}
