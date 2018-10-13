#!/bin/bash
docker build -t paperbenni/rclone .
docker push paperbenni/rclone > /dev/null &