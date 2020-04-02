
FROM paperbenni/alpine

RUN wget -O /usr/bin/serveo 'https://storage.googleapis.com/serveo/download/2018-05-08/serveo-linux-amd64' && \
    chmod +x /usr/bin/serveo

RUN apk add expect
COPY keygen.sh /usr/bin/keygen.sh
COPY start.sh start.sh
RUN chmod +x start.sh

CMD ./start.sh