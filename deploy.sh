#!/bin/bash
# script to build and deploy coldcrypt
# NOTE: building and deployment should be from the github action automatically
git pull
rm coldcrypt 2>/dev/null
VERSION=$(git describe --tags --always --dirty 2>/dev/null || git rev-parse --short HEAD)
go build -ldflags "-X main.Version=${VERSION}" ./cmd/coldcrypt/
mv coldcrypt /usr/local/bin/
chown coldcrypt:coldcrypt /usr/local/bin/coldcrypt
systemctl restart coldcrypt
