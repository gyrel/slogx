.PHONY: test lint fmt examples pre-release coverage

test:
	GOWORK=off go test ./... -race -count=1

lint:
	GOWORK=off golangci-lint run --timeout=5m

fmt:
	gofmt -w .

examples:
	@for d in examples/*/; do echo "==> $$d"; GOWORK=off go run "./$$d"; done

coverage:
	GOWORK=off go list ./... | grep -v '/examples/' | \
	  xargs env GOWORK=off go test -count=1 -coverprofile=coverage.out -covermode=atomic
	GOWORK=off go tool cover -func=coverage.out | tail -1

pre-release:
	bash scripts/pre-release-check.sh

pre-release-quick:
	bash scripts/pre-release-check.sh --quick
