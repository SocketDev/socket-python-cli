FROM python:3-alpine
LABEL org.opencontainers.image.authors="socket.dev"
ARG CLI_VERSION
ARG SDK_VERSION
ARG PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_EXTRA_INDEX_URL=https://pypi.org/simple

RUN apk update \
    && apk add --no-cache git nodejs npm yarn

# Install CLI and optionally override SDK version
RUN pip install --index-url ${PIP_INDEX_URL} --extra-index-url ${PIP_EXTRA_INDEX_URL} socketsecurity==$CLI_VERSION \
    && if [ ! -z "$SDK_VERSION" ]; then \
       pip install --index-url ${PIP_INDEX_URL} --extra-index-url ${PIP_EXTRA_INDEX_URL} socket-sdk-python==${SDK_VERSION}; \
    fi