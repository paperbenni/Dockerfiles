#!/bin/bash

DOCKERNAME="$(ls | fzf)"
[ -z "$DOCKERNAME" ] && exit
[ -e ./"$DOCKERNAME/Dockerfile" ] || exit 1

cd "$DOCKERNAME"
DOCKERUSER="$(docker info | grep Username | head -1 | sed 's/^[^:]*: //g')"

[ -z "$DOCKERUSER" ] && {
    echo "please log into docker hub"
    exit 1
}

docker build -t "$DOCKERUSER"/"$DOCKERNAME" .

