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

package kubecover

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/golang/glog"
)

// decodeInput decodes the json payload
func (r *KubeCover) decodeInput(req *http.Request, data interface{}) (string, error) {
	// step: read in the content payload
	content, err := ioutil.ReadAll(req.Body)
	if err != nil {
		glog.Errorf("unable to read in the content, error: %s", err)
		return "", err
	}
	defer func() {
		// we need to set the content back
		req.Body = ioutil.NopCloser(bytes.NewReader(content))
	}()

	rdr := strings.NewReader(string(content))

	// step: decode the json
	err = json.NewDecoder(rdr).Decode(data)
	if err != nil {
		glog.Errorf("unable to decode the request body, error: %s", err)
		return "", err
	}

	return string(content), nil
}
