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
	"regexp"
)

func policyValid(policy *PodSecurityPolicyList) error {
	if len(policy.Items) <= 0 {
		return fmt.Errorf("the policy list has no items")
	}

	for i, x := range policy.Items {
		if err := x.isValid(); err != nil {
			return fmt.Errorf("policy spec %d invalid, error: %s", i, err)
		}
	}

	return nil
}

func (r *PodSecurityPolicy) isValid() error {
	if len(r.Namespaces) <= 0 {
		return fmt.Errorf("the policy does not have any namespaces")
	}
	if r.Spec == nil {
		return fmt.Errorf("the policy does not have a spec")
	}
	if err := r.Spec.isValid(); err != nil {
		return err
	}

	return nil
}

func (r *PodSecurityPolicySpec) isValid() error {
	if r.Images != nil {
		if err := r.Images.isValid(); err != nil {
			return err
		}
	}

	for _, x := range r.HostPorts {
		if err := x.isValid(); err != nil {
			return err
		}
	}

	return nil
}

func (r *ImageSecurityPolicy) isValid() error {
	r.matches = make(map[*regexp.Regexp]bool, 0)

	for _, x := range r.Denied {
		reg, err := regexp.Compile(x)
		if err != nil {
			return fmt.Errorf("regex: %s is invalid", x)
		}
		r.matches[reg] = false
	}

	for _, x := range r.Permitted {
		reg, err := regexp.Compile(x)
		if err != nil {
			return fmt.Errorf("regex: %s is invalid", x)
		}
		r.matches[reg] = true
	}

	return nil
}

func (r *HostPortRange) isValid() error {
	if r.Start > r.End {
		return fmt.Errorf("the start port cannout be greater than end")
	}
	if r.Start <= 0 || r.Start >= 65535 {
		return fmt.Errorf("the start port in invalid 1->65534")
	}
	if r.End <= 0 || r.End >= 65535 {
		return fmt.Errorf("the start port in invalid 1->65534")
	}

	return nil
}