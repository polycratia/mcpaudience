GO ?= go

.PHONY: test fmt demo

test:
	$(GO) vet ./...
	$(GO) test ./...

fmt:
	gofmt -w .

demo:
	$(GO) run ./example
