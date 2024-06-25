FROM python:3-alpine
LABEL org.opencontainers.image.authors="socket.dev"
ARG CLI_VERSION
RUN apk update \
    && apk add --no-cache git nodejs npm yarn
RUN pip install socketsecurity --upgrade \
    && socketcli -v \
    && socketcli -v | grep -q $CLI_VERSION