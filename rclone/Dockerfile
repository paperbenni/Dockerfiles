FROM alpine:3.18.3
RUN apk update && apk add unzip curl git man bash
RUN mkdir -p /home/user/path
ENV HOME=/home/user
WORKDIR /home/user
COPY install.sh install.sh
RUN bash install.sh
CMD bash