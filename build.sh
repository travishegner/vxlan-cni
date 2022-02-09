#!/bin/bash

CGO_ENABLED=0 go build -o bin/vxlan vxlan/main.go
