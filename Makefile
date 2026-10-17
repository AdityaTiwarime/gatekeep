VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: test race fuzz build cross deb docker demo e2e clean

test:
	go vet ./...
	go test ./...

race:
	go test -race -count=1 ./...

fuzz:
	go test ./internal/jwt -run xxx -fuzz FuzzParse -fuzztime 30s

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gatekeep ./cmd/gatekeep

# Static binaries for Linux (amd64/arm64), Windows and macOS.
cross:
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/gatekeep-linux-amd64 ./cmd/gatekeep
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/gatekeep-linux-arm64 ./cmd/gatekeep
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/gatekeep-windows-amd64.exe ./cmd/gatekeep
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/gatekeep-darwin-arm64 ./cmd/gatekeep

deb:
	./scripts/package-deb.sh $(VERSION) amd64

docker:
	docker build -t gatekeep:$(VERSION) .

demo: build
	./bin/gatekeep demo -addr :8080

# Starts the demo, runs the curl walkthrough against it, stops it.
e2e: build
	./bin/gatekeep demo -addr 127.0.0.1:8099 > /tmp/gatekeep-e2e.log 2>&1 & echo $$! > /tmp/gatekeep-e2e.pid
	sleep 1
	./scripts/demo.sh http://localhost:8099; status=$$?; kill $$(cat /tmp/gatekeep-e2e.pid); exit $$status

clean:
	rm -rf bin dist
