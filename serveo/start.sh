#!/bin/bash

echo "starting serveo"
[ -e /root/.ssh ] && rm -rf /root/.ssh
[ -e /home/user/.ssh ] && rm -rf /home/user/.ssh

expect /usr/bin/keygen.sh

/usr/bin/serveo -private_key_path=/root/.ssh/id_rsa -port=2222
