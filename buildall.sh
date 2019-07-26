#!/bin/bash

# iterate over folders, build and push images in them
for DOCKER in ./*; do
    DOCKERNAME=${DOCKER#./}
    if ! [ -e "$DOCKER/Dockerfile" ]; then
        continue
    fi
    cd "$DOCKER"
    docker build -t paperbenni/"$DOCKERNAME" .
    docker push paperbenni/"$DOCKERNAME"
    cd ..
done
