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
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/gambol99/kube-cover/utils"
)

// parsePolicyFile reads in the policy file
func parsePolicyFile(path string) (*PodSecurityPolicyList, error) {
	// step: check the file exists
	if found := utils.FileExists(path); !found {
		return nil, fmt.Errorf("file %s does not exist", path)
	}

	// step: check the extension
	ext := filepath.Ext(path)
	switch ext {
	case ".json":
	case ".yml":
	case ".yaml":
	default:
		return nil, fmt.Errorf("unsupported extension and policy file format")
	}

	// step: decode the policy
	policy, err := decodePolicyFile(path)
	if err != nil {
		return nil, err
	}

	// step: validate and finesse the policy
	if err := policyValid(policy); err != nil {
		return nil, err
	}

	fmt.Printf("IMAGE: %v\n", policy.Items)

	return policy, nil
}

// decodePolicyFile decodes the policy file
func decodePolicyFile(path string) (*PodSecurityPolicyList, error) {
	var err error
	policy := new(PodSecurityPolicyList)

	// step: read in the content of the file
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	extension := filepath.Ext(path)
	switch extension {
	case ".yaml":
		fallthrough
	case ".yml":
		err = yaml.Unmarshal(content, policy)
	default:
		err = json.NewDecoder(strings.NewReader(string(content))).Decode(policy)
	}

	if err != nil {
		return nil, err
	}

	return policy, nil
}
