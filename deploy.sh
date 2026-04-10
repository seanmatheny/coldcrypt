#!/bin/bash
cd /root/bin/coldcrypt
git pull
rm coldcrypt
go build ./cmd/coldcrypt/
mv coldcrypt /usr/local/bin/
chown coldcrypt:coldcrypt /usr/local/bin/coldcrypt
systemctl restart coldcrypt