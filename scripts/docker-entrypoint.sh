#!/bin/sh

# Docker entrypoint script to support both patterns:
# docker run socketdev/cli socketcli --params
# docker run socketdev/cli --cli-params

# Set GOROOT from the value determined at build time
export GOROOT=$(cat /etc/goroot)

# Check if we have any arguments
if [ $# -eq 0 ]; then
    # No arguments provided, run socketcli with no args (will show help)
    exec socketcli --help
elif [ "$1" = "socketcli" ]; then
    # If first argument is "socketcli", shift it out and pass the rest to socketcli
    shift
    exec socketcli "$@"
else
    # If first argument is not "socketcli", assume all arguments are for socketcli
    exec socketcli "$@"
fi