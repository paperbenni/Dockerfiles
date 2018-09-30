#!/bin/bash
for DOCKER in ./*; do
	if [ -e "$DOCKER/build.sh" ]; then
		bash "$DOCKER/build.sh"
	fi
    sleep 1
    echo "next one!"
done