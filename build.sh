#!/bin/bash

##############################
# Build vuln.c through rootless podman
##############################
podman build -f gcc.Dockerfile -t gcc:arm32 .
podman run -it --rm -v "$(pwd)":/app --workdir /app gcc:arm32 make
