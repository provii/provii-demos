# Makefile for Go Verifier Backend Demo

.PHONY: run build clean generate-openapi

# Run the server
run:
	go run main.go

# Build the server binary
build:
	go build -o server main.go

# Generate OpenAPI specification
generate-openapi:
	go run openapi_gen.go > openapi.json

# Clean build artifacts
clean:
	rm -f server openapi.json
