FROM ubuntu
RUN mkdir -p /home/user
ENV HOME=/home/user
RUN apt-get update && apt-get upgrade -y && apt-get install -y curl git neovim wget subversion
CMD bash