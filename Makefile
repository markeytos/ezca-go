GO_DIRS=$(shell find . -type d)
GO_FILES=$(shell find . -type f -name '*.go')

./bin/ezca: $(GO_DIRS) $(GO_FILES)
	@mkdir -p bin
	go build -o $@ ./cmd/ezca/

.PHONY: checks
checks:
	go fmt ./...
	go vet ./...
	go mod tidy
	golangci-lint run ./...

.PHONY: test
test:
	go test ./...

covprofile: $(GO_DIRS) $(GO_FILES)
	go test -race -covermode=atomic -coverprofile=covprofile ./...
	grep -vFf .test_cover_ignore covprofile | sponge covprofile

.PHONY: cover-http
http-cover: covprofile
	go tool cover -html=$<

.PHONY: clean
clean:
	rm -rf bin
