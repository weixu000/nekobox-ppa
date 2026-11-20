FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db

# Build dependencies stay inside this disposable environment.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake debhelper devscripts dpkg-dev \
    file git golang-go linguist-qt6 patchelf pkg-config \
    qt6-base-dev qt6-base-dev-tools qt6-tools-dev qt6-tools-dev-tools \
    qt6-declarative-dev thrift-compiler libthrift-dev libacl1-dev \
    libboost-all-dev liblmdb-dev libunistring-dev libzstd-dev \
    libcurl4-openssl-dev libyaml-cpp-dev libleveldb-dev libsnappy-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
