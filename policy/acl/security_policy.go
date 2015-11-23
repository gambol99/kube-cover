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
	"github.com/gambol99/kube-cover/utils"
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
	// check for users
	if found := utils.ContainedIn(cx.User, r.Users); found {
		return true
	}
	// check the groups
	for _, name := range cx.Groups {
		if found := utils.ContainedIn(name, r.Groups); found {
			return true
		}
	}

	return false
}
