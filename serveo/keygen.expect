#!/usr/bin/expect
set timeout 100000

spawn ssh-keygen
expect "/root/."
send "\n"
expect "passphrase"
send "\n"
expect "again"
send "\n"
