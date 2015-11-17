FROM alpine:latest
MAINTAINER Rohith <gambol99@gmail.com>

ADD https://github.com/gambol99/kube-cover/releases/download/0.0.1/kube-cover_0.0.1_linux_x86_64.gz /kube-cover
RUN chmod +x /kube-cover
EXPOSE 80 443

ENTRYPOINT [ "/kube-cover" ]
