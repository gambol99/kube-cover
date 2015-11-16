
### **Kube Cover**
---

**Kube Cover** is a short-term hack to enable security policies via the Kuberneres API. Presently, items such as privileged, host network, host, pid/ipc, host port range and docker capabilities are difficult or in some cases impossible to enforce a security policy. Kube Cover provide's a stepping stone into using  those policies while we wait for the kubernetes project to resolve and release them. Note, the actually policies are based on a PR released into Openshift Origin


##### **Usage**
----
```shell
Usage of bin/kube-cover:
  -alsologtostderr          log to standard error as well as files
  -bind string              the interface and port for the service to listen on (default ":6444")
  -log_backtrace_at value   when logging hits line file:N, emit a stack trace (default :0)
  -log_dir string           If non-empty, write log files in this directory
  -logtostderr              log to standard error instead of files
  -policy-file string       the path to the policy file container authorization security policies
  -stderrthreshold value    logs at or above this threshold go to stderr
  -tls-cert string          the path to the tls cerfiicate for the service to use
  -tls-key string           the path to the tls private key for the service
  -url string               the url for the kubernetes upstream api service, must be https (default "https://127.0.0.1:6443")
  -v value                  log level for V logs
  -vmodule value            comma-separated list of pattern=N settings for file-filtered logging
```

##### **Example Usage**
----
```shell
[jest@starfury kube-cover]$ bin/kube-cover \
    -logtostderr=true -v=10 \
    -tls-cert=tests/kubeapi.pem \
    -tls-key=tests/kubeapi-key.pem \
    -policy-file=tests/policies.json \
    -url=https://the_url_for_the_k8s_api_must_be_https

[jest@starfury openvpn]$ kubectl get pods
NAME            READY     STATUS                                         RESTARTS   AGE
service-u6ea0   0/1       Image: nginx is ready, container is creating   0          2h
web-7jthn       1/1       Running                                        0          1d

I1116 16:34:49.748882   30023 server.go:32] create a new kube cover service
I1116 16:34:49.749001   30023 controller.go:41] loading the policies file: tests/policies.json
I1116 16:34:49.749355   30023 controller.go:46] found 1 polices in the file
[GIN] 2015/11/16 - 16:35:13 | 200 |  130.948277ms | 127.0.0.1 |   GET     /api
[GIN] 2015/11/16 - 16:35:13 | 200 |   28.218429ms | 127.0.0.1 |   GET     /api/v1/namespaces/default/pods

# attempt to create a pod with a hostpath mapped into /etc
[jest@starfury kube-cover]$ kubectl create -f tests/services/service-hostpaths.yml 
Error from server: error when creating "tests/services/service-hostpaths.yml": security policy violation, reason: host path /run/vault

# logging from the kube-cover proxy filter

[GIN] 2015/11/16 - 16:38:13 | 200 |   55.299491ms | 127.0.0.1 |   GET     /api
I1116 16:38:13.587799   30023 handlers.go:48] authorizating replication controller, namespace: default, name: service
I1116 16:38:13.587823   30023 controller.go:56] validating the pod spec, namespace: default
E1116 16:38:13.587832   30023 handlers.go:86] unauthorized request from: (127.0.0.1:44040), failure: host path /run/vault violation
E1116 16:38:13.587836   30023 handlers.go:87] failing specification: 

.. -> plus a insert of pod json which violated the policy

```

##### **Security Policies**

The security policy file is a single json file containing an array of PodSecurityPolicy types (which you can find in
policy/acl/types.go)

At the moment the filter / matching for security policies is applied at a *namespace* level (since that's what were using use to segregate projects  - we then use a [auth-policy](https://github.com/kubernetes/kubernetes/blob/release-1.1/docs/admin/authorization.md) to enforce which namespaces a user has permissions to access. You could technically grab the user / group from a JWT or tokenfile, **BUT**, depends on how long it takes for k8s to merge the security policy proposal.

```JSON
{
  "kind": "PodSecurityPolicyList",
  "apiVersion": "v1",
  "items": [
    {
      "kind": "PodSecurityPolicy",
      "version": "v1",
      "namespaces": [
        "*"
      ],
      "spec": {
        "privileged" : false,
        "hostNetwork" : false,
        "hostPID": false,
        "hostIPC": false,
        "volumes": {
          "hostPath": true,
          "hostPathAllowed": [
            "/var/data"
          ],
          "emptyDir": true,
          "gitRepo": true,
          "secret": true,
          "rbd": true,
          "downwardAPI": true
        }
      }
    }
  ]
}
```

##### **Todo**

- Need to fixup the code for connection hijacking and permitting the **kubectl exec** command to work (this requires the connection is upgraded into a spdy stream).

