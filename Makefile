run: build
	@./bin/golinux

build:
	@go mod tidy
	@go build -o bin/golinux .