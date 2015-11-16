
##### **Generating a Certificate via Cloudflare cfssl**

```shell
$ cfssl genkey -initca ca-csr.json | cfssljson -bare ca
$ cfssl gencert -ca=ca.pem   -ca-key=ca-key.pem -config=ca-config.json -profile=server kube-apiserver-csr.json | cfssljson -bare kubeapi
```
