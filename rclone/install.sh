curl -o rclone.zip https://downloads.rclone.org/rclone-current-linux-amd64.zip
unzip rclone.zip
rm rclone.zip
mv rclone-v1.43.1-linux-amd64/* path/
echo "export PATH=/home/user/path:$PATH" >> $HOME/.bashrc