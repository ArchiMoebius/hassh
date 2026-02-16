BUILD=$(shell git rev-parse HEAD)
BASEDIR=./dist
DIR=${BASEDIR}/temp

BUILD_UUID=$(shell cat /proc/sys/kernel/random/uuid)

LDFLAGS=-ldflags "-s -w -X 'main.build=${BUILD}' -buildid=${BUILD}"
GCFLAGS=-gcflags=all=-trimpath=$(shell pwd)
ASMFLAGS=-asmflags=all=-trimpath=$(shell pwd)

GOFILES=`go list -buildvcs=false ./...`
GOFILESNOTEST=`go list -buildvcs=false ./... | grep -v test`

# Make Directory to store executables
$(shell mkdir -p ${DIR})

all: linux
# goreleaser build --config .goreleaser.yml --snapshot --clean

linux: lint security
	@env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/hassh-proxy-linux_amd64 cmd/sshproxy/main.go
	@env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/hassh-ctl-linux_amd64 cmd/sshctl/main.go

tidy:
	@go mod tidy

update: tidy
	@go get -v -d ./...
	@go get -u all

dep: ## Get the dependencies
	@git config --global url."git@github.com:".insteadOf "https://github.com/"
	@go install github.com/boumenot/gocover-cobertura@latest
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@go install github.com/goreleaser/goreleaser/v2@latest
	@curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.9.0

lint:
	@env CGO_ENABLED=0 go fmt ${GOFILES}
	@env CGO_ENABLED=0 go vet ${GOFILESNOTEST}
	@golangci-lint run ./...

security: tidy
	@go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...
	@go run github.com/go-critic/go-critic/cmd/gocritic@latest check -enableAll -disable='#experimental,#opinionated' ./...
	@go run github.com/google/osv-scanner/cmd/osv-scanner@latest -r . || echo "oh snap!"

release:
	@goreleaser release --config .github/goreleaser.yml

clean:
	@rm -rf ${BASEDIR}

.PHONY: all freebsd linux submodule tidy update dep lint security test release clean
