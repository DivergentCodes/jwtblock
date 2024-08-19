# JWT Block

[![Go Reference](https://pkg.go.dev/badge/github.com/divergentcodes/jwtblock.svg)](https://pkg.go.dev/github.com/divergentcodes/jwtblock)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/DivergentCodes/jwtblock/release.yaml?style=flat-square)](https://github.com/DivergentCodes/jwtblock/actions?query=workflow%3Arelease)

Exploring the feasability and performance of a JWT blocklist.

## About

JWT Block is a blocklist & forward auth proxy service for JWTs, to support
immediatetermination of access, since access tokens cannot truly be revoked.

It is a standalone binary that requires a Redis instance to store the blocklist.

It can be run as a web service or an AWS Lambda authorizer.

## Installation

### Build From Source

1. Have a functional Golang development environment.
2. Build and install: `make && make install`

### Binary Release

1. Download the [binary release](https://github.com/DivergentCodes/jwtblock/releases)
for your platform
2. Place the `jwtblock` binary in an executable path.

### Docker

JWT Block is available as [a Docker image](https://hub.docker.com/r/divergentcodes/jwtblock).

```
docker run --rm -it divergentcodes/jwtblock:latest
```

## Usage

### CLI

```
JWT Block is a blocklist & auth proxy service for JWTs, to support immediate termination of access, since access tokens cannot truly be revoked.

Usage:
  jwtblock [command]

Available Commands:
  block       Block a JWT
  check       Check if a JWT is blocked
  completion  Generate the autocompletion script for the specified shell
  flush       Empty the blocklist
  help        Help about any command
  list        List blocked JWT hashes
  openapi     Generate OpenAPI specs for jwtblock
  serve       Serve the web API
  status      Get status of the blocklist
  unblock     Unblock a JWT
  version     Print the version of jwtblock

Flags:
      --config string       config file (default is ./jwtblock.yaml)
      --debug               Enable debug mode
  -h, --help                help for jwtblock
      --json                Use JSON log output
  -q, --quiet               Quiet CLI output
      --redis-dbnum int     Redis DB number
      --redis-host string   Redis host (default "localhost")
      --redis-noverify      Skip Redis TLS certificate verification
      --redis-pass string   Redis password
      --redis-port int      Redis port (default 6379)
      --redis-tls           Connect to Redis over TLS
      --redis-user string   Redis username
      --verbose             Verbose CLI output

Use "jwtblock [command] --help" for more information about a command.
```

### API

The web service listens on port `4474/tcp` by default. It has two primary
API endpoints, one for adding tokens to the blocklist (e.g. "logout") and
one to check whether a token is in the blocklist.

- `POST /blocklist/block`
- `GET /blocklist/check`

Both endpoints parse the token from the `Authorization` header as a
bearer token. No other parameters are needed.

Start the web service with `jwtblock serve`.

OpenAPI specs can be generated with `jwtblock openapi`.

### AWS Lambda

> [!TIP]
> Check the full [AWS Lambda example](./examples/aws-lambda-authorizer/README.md).

JWT Block can run as an AWS Lambda function that will handle the following events:
- API Gateway AWS Proxy: handle HTTP requests from API Gateway to block a token.
- API Gateway Authorizer: make authentication decisions for API Gateway, similar to "forward auth" proxies.

### Configuration

There are multiple ways to configure JWT Block (in order of precedence):
- CLI argument flags.
- Environment variables.
- Configuration file.

## Demo

> [!TIP]
> The easiest way to try JWT Block is to spin up the [Docker Compose example](./examples/docker-compose/README.md).

Run a Redis instance and then start the web service with the `serve` subcommand.

```sh
$ docker run -d --rm -p6379:6379 redis:alpine
402f9668087f59fa085f6bcf5f40db441291f74b6399023a17654575d6d1dc95

$ jwtblock serve
JWT Block 0.0.1-DEV-SNAPSHOT-c7d8e29 created by Jack Sullivan <jack@divergent.codes>

Serving the jwtblock web API on :4474
{"level":"info","message":"Serving web API","func":"HandleRequests","host":"","port":4474}
```

Send requests to the service to block a token and verify that it is blocked.

```sh
export JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzIyNzIyODg4LCJleHAiOjE3MjI3MjY0ODh9.jPZiGRRudxPAku-FBiWHrxyn95Zj01Pm6ZiUw097fcE"

$ curl -s -X GET http://jwtblock.localhost:4474/blocklist/check \
  -H "Authorization: Bearer $JWT" \
  | jq
{
  "message": "JWT is allowed",
  "blocked": false,
  "block_ttl_sec": -1,
  "block_ttl_str": "",
  "error": false
}

$ curl -s -X POST http://jwtblock.localhost:4474/blocklist/block \
  -H "Authorization: Bearer $JWT" \
  | jq
{
  "message": "Token blocked",
  "error": false
}

$ curl -s -X GET http://jwtblock.localhost:4474/blocklist/check \
  -H "Authorization: Bearer $JWT" \
  | jq
{
  "message": "JWT is blocked",
  "blocked": true,
  "block_ttl_sec": 3463,
  "block_ttl_str": "57m43s",
  "error": false
}
```

The blocklist can be managed with the CLI.

```sh
$ jwtblock --quiet status
Blocklist size: 1

$ jwtblock --quiet list
{"level":"info","message":"Listed token hashes in the blocklist","size":1}
0: b8a5471d47b724b277d4861db071ae817556655abd9f31ce7cfa8b055cf9e397

$ jwtblock --quiet flush
{"level":"info","message":"Flushed the blocklist","count":1,"result":{"message":"OK","count":1,"error":false}}
Flushed 1 tokens from the blocklist

$ jwtblock --quiet status
Blocklist size: 0
```
