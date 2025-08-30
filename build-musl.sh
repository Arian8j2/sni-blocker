#!/bin/bash

IMAGE=builder
CONTAINER=temp-builder

docker build -t $IMAGE -f - . <<EOF
    FROM rust:1.89.0-alpine3.22
    RUN apk update && apk add --no-cache build-base libpcap-dev
    COPY . .
    RUN cargo clean && cargo b --release
EOF

docker create --name $CONTAINER $IMAGE
docker cp $CONTAINER:target/release/sni-blocker .
docker rm $CONTAINER
