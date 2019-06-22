FROM paperbenni/ubuntu
COPY install.sh install.sh
RUN bash install.sh && rm install.sh

RUN curl https://cli-assets.heroku.com/install.sh | sh

RUN heroku --version
