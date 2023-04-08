#!/bin/bash

go install github.com/securego/gosec/v2/cmd/gosec@latest

# G101: "possible hardcoded secret" triggers false positives.
# G402: "TLS InsecureSkipVerify set true" triggers false positives.
gosec -exclude=G101,G402 ./...
