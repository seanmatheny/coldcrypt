#!/bin/bash
# script to build and deploy coldcrypt
# NOTE: building and deployment should be from the github action automatically
git pull
rm coldcrypt 2>/dev/null
go build ./cmd/coldcrypt/
mv coldcrypt /usr/local/bin/
chown coldcrypt:coldcrypt /usr/local/bin/coldcrypt
systemctl restart coldcrypt
