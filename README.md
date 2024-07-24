# JWT Block

[![Go Reference](https://pkg.go.dev/badge/github.com/divergentcodes/jwtblock.svg)](https://pkg.go.dev/github.com/divergentcodes/jwtblock)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/DivergentCodes/jwtblock/release.yaml?style=flat-square)](https://github.com/DivergentCodes/jwtblock/actions?query=workflow%3Arelease)

Exploring the feasability and performance of a JWT blocklist.

## About

JWT Block is a blocklist & auth proxy service for JWTs, to support immediate termination of access, since access tokens cannot truly be revoked.

It is a standalone binary that requires a Redis instance to store the blocklist.

## Installation

Download the [binary release](https://github.com/DivergentCodes/jwtblock/releases) for your platform,
and place it in the executable path.

JWT Block is also available as [a Docker image](https://hub.docker.com/r/divergentcodes/jwtblock).

```
docker run -it --rm divergentcodes/jwtblock:latest
```


## Usage

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
  serve       Serve the web API
  status      Get status of the blocklist
  unblock     Unblock a JWT
  version     Print the version of jwtblock

Flags:
      --config string       config file (default is ./jwtblock.yaml)
      --debug               Enable debug mode
  -h, --help                help for jwtblock
      --json                Use JSON output
  -q, --quiet               Quiet CLI output
      --redis-dbnum int     Redis DB number
      --redis-host string   Redis host (default "localhost")
      --redis-noverify      Skip Redis TLS certificate verification
      --redis-pass string   Redis password
      --redis-port int      Redis port (default 6379)
      --redis-tls           Connect to Redis over TLS (default true)
      --redis-user string   Redis username
      --verbose             Verbose CLI output

Use "jwtblock [command] --help" for more information about a command.
```

## Configuration

There are a few ways to configure JWT Block (in order of precedence):
- CLI argument flags.
- Environment variables.
- Configuration file.
