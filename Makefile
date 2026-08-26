.PHONY: all build clean run cross

BINARY_NAME=pingo-server

all: build

build:
	go build -ldflags="-s -w" -o $(BINARY_NAME) .

run: build
	./$(BINARY_NAME)

cross:
	./build.sh

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/
