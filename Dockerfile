FROM python:3-alpine
LABEL org.opencontainers.image.authors="socket.dev"
ARG CLI_VERSION
ARG SDK_VERSION
ARG PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_EXTRA_INDEX_URL=https://pypi.org/simple

RUN apk update \
    && apk add --no-cache git nodejs npm yarn

# Install CLI with retries for TestPyPI propagation (10 attempts, 30s each = 5 minutes total)
RUN for i in $(seq 1 10); do \
        echo "Attempt $i/10: Installing socketsecurity==$CLI_VERSION"; \
        if pip install --index-url ${PIP_INDEX_URL} --extra-index-url ${PIP_EXTRA_INDEX_URL} socketsecurity==$CLI_VERSION; then \
            break; \
        fi; \
        echo "Install failed, waiting 30s before retry..."; \
        sleep 30; \
    done && \
    if [ ! -z "$SDK_VERSION" ]; then \
        pip install --index-url ${PIP_INDEX_URL} --extra-index-url ${PIP_EXTRA_INDEX_URL} socketdev==${SDK_VERSION}; \
    fi