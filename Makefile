all: build/vxlan

rebuild: clean build/vxlan

clean:
	rm -rf build/*

build/vxlan: lint
	CGO_ENABLED=0 go build -o build/vxlan

lint:
	golint -set_exit_status ./...

.PHONY: all clean lint