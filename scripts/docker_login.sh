#!/bin/bash

# Login to the Docker registry.
echo "$DOCKER_API_KEY" | docker login -u "$DOCKER_USERNAME" --password-stdin
