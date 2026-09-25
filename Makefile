GO ?= go

.PHONY: test fmt demo demo-mcp

test:
	$(GO) vet ./...
	$(GO) test ./...

fmt:
	gofmt -w .

demo:
	$(GO) run ./example

demo-mcp:
	$(GO) run ./example/mcpsdk
