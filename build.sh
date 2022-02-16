#!/bin/bash

mkdir -p build || true
CGO_ENABLED=0 go build -o build/vxlan .
