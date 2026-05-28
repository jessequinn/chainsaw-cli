VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build clean test lint fmt scan

build:
	go build $(LDFLAGS) -o chainsaw ./cmd/chainsaw

clean:
	rm -f chainsaw

test:
	go test -race -coverprofile=coverage.txt -covermode=atomic ./...

lint:
	golangci-lint run

fmt:
	gofmt -s -w .

# Dogfood: scan ourselves
scan: build
	./chainsaw scan .
