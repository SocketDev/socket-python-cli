FROM python:3-alpine
LABEL org.opencontainers.image.authors="socket.dev"
ARG CLI_VERSION
ARG PIP_INDEX_URL=https://pypi.org/simple
RUN apk update \
    && apk add --no-cache git nodejs npm yarn

RUN pip install --index-url ${PIP_INDEX_URL} socketsecurity==$CLI_VERSION \
    && socketcli -v \
    && socketcli -v | grep -q $CLI_VERSION

# !! Uncomment to test local build - requires running `python -m build` first (and correct version number)
# COPY dist/socketsecurity-1.0.34-py3-none-any.whl /tmp/
# RUN pip install /tmp/socketsecurity-1.0.34-py3-none-any.whl \
#     && socketcli -v \
#     && socketcli -v | grep -q $CLI_VERSION