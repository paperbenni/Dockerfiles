FROM ubuntu:20.04
RUN mkdir -p /home/user
ENV HOME=/home/user
WORKDIR /home/user
RUN apt-get update && apt-get upgrade -y && apt-get install -y curl git neovim wget subversion
CMD bash
