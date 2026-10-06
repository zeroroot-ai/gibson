BINARY   := gitlab
MANIFEST := ./plugin.yaml
TOKEN    ?=

.PHONY: build test register run image

## build: compile the plugin binary (CGO_ENABLED=0).
build:
	CGO_ENABLED=0 go build -o $(BINARY) .

## test: run the hermetic handler tests (cassette replay, no daemon/network).
test:
	go test ./...

## register: first-time registration with the Gibson daemon.
## Usage: make register TOKEN=<bootstrap-token>
register:
	@if [ -z "$(TOKEN)" ]; then echo "TOKEN is required: make register TOKEN=<bootstrap-token>"; exit 1; fi
	gibson component register --token "$(TOKEN)"

## run: start the plugin via the CLI's process supervisor.
run: build
	gibson component run

## image: build the container image. The build context is the repository
## root, because LICENSE lives there and the image has to carry it.
image:
	cd ../.. && docker build -f plugins/gitlab/Dockerfile -t gibson-plugin-gitlab:dev .
