.PHONY: test vet build clean

BINARY ?= palm

test:
	go test ./...

vet:
	go vet ./...

build:
	go build -o $(BINARY) .

clean:
	rm -f palm palm.exe
