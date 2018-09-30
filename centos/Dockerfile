FROM centos
RUN mkdir -p /home/user
RUN yum update -y && yum install -y curl git bash vim
ENV HOME=/home/user
CMD [ "/bin/bash" ]