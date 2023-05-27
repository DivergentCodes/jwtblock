#!/bin/bash

# Push the created Docker image to the repository, with all associated tags.
echo "$DOCKER_API_KEY" | docker login -u "$DOCKER_USERNAME" --password-stdin
docker image push --all-tags divergentcodes/jwt-block
