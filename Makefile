GO ?= go

build:
	$(GO) build -o vulngate ./cmd/vulngate

install: build
	$(GO) install ./cmd/vulngate
	@echo "installed to $$(go env GOBIN 2>/dev/null || echo "$$HOME/go/bin")/vulngate"

test:
	$(GO) test ./...

bench: build
	./vulngate scan --format=json bench/corpus > bench/vg_pred.json
	python3 bench/score.py bench/vg_pred.json

clean:
	rm -f vulngate bench/vg_pred.json bench/vg_*.json

.PHONY: build install test bench clean
