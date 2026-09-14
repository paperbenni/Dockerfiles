#!/bin/bash

DOCKERNAME="$(find . -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort | fzf)"
[ -z "$DOCKERNAME" ] && exit
[ -e ./"$DOCKERNAME/Dockerfile" ] || exit 1

cd "$DOCKERNAME" || exit
DOCKERUSER="$(docker info | grep Username | head -1 | sed 's/^[^:]*: //g')"

[ -z "$DOCKERUSER" ] && {
    echo "please log into docker hub"
    exit 1
}

docker build -t "$DOCKERUSER"/"$DOCKERNAME" .
