
NAME=kube-cover
AUTHOR=gambol99
HARDWARE=$(shell uname -m)
VERSION=$(shell awk '/version =/ { print $$3 }' doc.go | sed 's/"//g')
DEPS=$(shell go list -f '{{range .TestImports}}{{.}} {{end}}' ./...)
PACKAGES=$(shell go list ./...)
VETARGS?=-asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -shift -structtags -unsafeptr

.PHONY: test authors changelog build docker static release

default: build

build:
	@echo "--> Compiling the project"
	mkdir -p bin
	godep go build -o bin/${NAME}

docker:
	@echo "--> Building the docker image"
	sudo docker build -t docker.io/${AUTHOR}/${NAME}:${VERSION} .

push: docker
	@echo "--> Pushing the image to docker.io"
	sudo docker push docker.io/${AUTHOR}/${NAME}:${VERSION}

static:
	@echo "--> Compiling the static binary"
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux godep go build -a -tags netgo -ldflags '-w' -o bin/${NAME}

release: static
	mkdir -p release
	gzip -c bin/${NAME} > release/${NAME}_${VERSION}_linux_${HARDWARE}.gz
	rm -f release/${NAME}

clean:
	rm -rf ./bin 2>/dev/null
	rm -rf ./release 2>/dev/null

authors:
	@echo "--> Updating the AUTHORS"
	git log --format='%aN <%aE>' | sort -u > AUTHORS

vet:
	@echo "--> Running go tool vet $(VETARGS) ."
	@go tool vet 2>/dev/null ; if [ $$? -eq 3 ]; then \
		go get golang.org/x/tools/cmd/vet; \
	fi
	@go tool vet $(VETARGS) .

lint:
	@echo "--> Running golint"
	@which golint 2>/dev/null ; if [ $$? -eq 1 ]; then \
		go get -u github.com/golang/lint/golint; \
	fi
	@golint ./...

format:
	@echo "--> Running go fmt"
	@go fmt $(PACKAGES)

cover:
	@echo "--> Running go cover"
	@godep go test --cover

test:
	@echo "--> Running go tests"
	godep go test -v ${DEPS}
	@$(MAKE) cover

changelog: release
	git log $(shell git tag | tail -n1)..HEAD --no-merges --format=%B > changelog
