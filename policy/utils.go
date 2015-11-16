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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/gambol99/kube-cover/policy/acl"
	"github.com/gambol99/kube-cover/utils"
)

// parsePolicyFile reads in the policy file
func parsePolicyFile(path string) (*acl.PodSecurityPolicyList, error) {
	// step: check the file exists
	if found := utils.FileExists(path); !found {
		return nil, fmt.Errorf("file %s does not exist", path)
	}

	// step: read in the content of the file
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	list := new(acl.PodSecurityPolicyList)
	// step: decode the content json
	err = json.NewDecoder(strings.NewReader(string(content))).Decode(list)
	if err != nil {
		return list, err
	}

	return list, nil
}
