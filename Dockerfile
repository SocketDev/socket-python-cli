FROM python:3-alpine
LABEL org.opencontainers.image.authors="socket.dev"

RUN apk update \
    && apk add --no-cache git nodejs npm yarn
RUN pip install socketsecurity --upgrade