FROM alpine:3.15.3
RUN apk update && apk add bash git curl wget vim subversion busybox-extras autossh
RUN mkdir -p /home/user
RUN echo 'papertest(){ source <(curl -s https://raw.githubusercontent.com/paperbenni/bash/master/import.sh); }' >> /home/user/.bashrc
ENV HOME=/home/user
CMD bash
