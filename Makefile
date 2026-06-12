BINARY  := magpie
CMD     := ./cmd/magpie
BIN     := bin/$(BINARY)
UI_SRC  := $(HOME)/Proyectos/apps/ui
VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build install run test vet fmt tidy clean ui-sync

## ui-sync: copia el design system compartido (~/Proyectos/apps/ui) a web/static/ui
ui-sync:
	cp $(UI_SRC)/tokens.css $(UI_SRC)/base.css web/static/ui/

## build: compila el binario en ./bin/magpie
build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) $(CMD)

## install: instala el binario global (go env GOPATH/bin, en tu PATH)
install:
	go install -ldflags "$(LDFLAGS)" $(CMD)

## run: corre el server desde el código (sin instalar)
run:
	go run -ldflags "$(LDFLAGS)" $(CMD)

## test: corre toda la suite
test:
	go test ./...

## vet: análisis estático
vet:
	go vet ./...

## fmt: formatea el código
fmt:
	go fmt ./...

## tidy: ordena go.mod/go.sum
tidy:
	go mod tidy

## clean: borra binarios locales y la DB de dev
clean:
	rm -rf bin $(BINARY) magpie.db magpie.db-journal
