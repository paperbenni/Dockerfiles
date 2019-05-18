#!/bin/bash
for DOCKER in ./*; do
    if ! [ -d "$DOCKER" ]; then
        echo "skipping $DOCKER"
        continue
    fi
		FOLDER="${DOCKER#./}"
    echo "building $FOLDER"
    pushd "$FOLDER"
    pwd
    docker build -t paperbenni/"$FOLDER" .
    docker push paperbenni/"$FOLDER"
    popd
done
