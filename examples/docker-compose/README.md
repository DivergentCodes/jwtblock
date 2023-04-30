# Local Example Using Docker Compose

This example starts a series of Docker containers, including a demo UI app and an instance of JWT Block. An Nginx proxy accepts all incoming web connections for the `*.local` network. For calls to the protected API, `api.local`, Nginx will forward requests to JWT Block to check if the request token is both valid not blocked.


## Quick Start

Build the current code into a local Docker image, and serve the containers
using Docker Compose. Use `CTRL-C` to shut the container down.

```
make start
```

Stop and clear all of the containers.

```
make stop
```

