#!/bin/bash

set -e

curl -fsSLo rclone.zip https://downloads.rclone.org/rclone-current-linux-amd64.zip
unzip rclone.zip
rm rclone.zip
mv rclone-*-linux-amd64/* path/
echo "export PATH=/home/user/path:\$PATH" >>"$HOME/.bashrc"
