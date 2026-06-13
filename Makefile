BINARY  := magpie
CMD     := ./cmd/magpie
BIN     := bin/$(BINARY)
UI_SRC  := $(HOME)/Proyectos/apps/ui
VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/ezequielcamezzana/magpie/cmd/magpie/commands.Version=$(VERSION) \
           -X github.com/ezequielcamezzana/magpie/cmd/magpie/commands.Commit=$(COMMIT) \
           -X github.com/ezequielcamezzana/magpie/cmd/magpie/commands.Date=$(DATE)

.PHONY: build install run test vet fmt tidy clean ui-sync

## ui-sync: copy the shared design system (~/Proyectos/apps/ui) into internal/server/ui/static/ui
ui-sync:
	cp $(UI_SRC)/tokens.css $(UI_SRC)/base.css internal/server/ui/static/ui/

## build: build the binary into ./bin/magpie
build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) $(CMD)

## install: install the binary globally (go env GOPATH/bin, on your PATH)
install:
	go install -ldflags "$(LDFLAGS)" $(CMD)

## run: run the server from source (without installing)
run:
	go run -ldflags "$(LDFLAGS)" $(CMD)

## test: run the full suite
test:
	go test ./...

## vet: static analysis
vet:
	go vet ./...

## fmt: format the code
fmt:
	go fmt ./...

## tidy: tidy go.mod/go.sum
tidy:
	go mod tidy

## clean: remove local binaries and the dev DB
clean:
	rm -rf bin $(BINARY) magpie.db magpie.db-journal
