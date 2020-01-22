FROM alpine:3.11.2

RUN mkdir -p /opt/ndff
ADD build.sh /opt/ndff

RUN apk add --update \
    build-base \
    meson \
    git \
    autoconf \
    automake \
    make \
    clang \
    libtool \
    pkgconfig \
    ninja \
    json-c \
    json-c-dev \
    msgpack-c \
    msgpack-c-dev \
    gtest \
    gtest-dev \
    libpcap \
    libpcap-dev \
    && rm -rf /var/cache/apk/* \
    && cd /tmp \
    && git clone https://github.com/ntop/nDPI.git \
    && cd nDPI \
    && git checkout 98d9f524f9ff7746d0345939fe543020f8057212 \
    && ./autogen.sh \
    && ./configure \
    && make \
    && make install \
    && cd .. \
    && rm -rf nDPI

WORKDIR /opt/ndff
CMD ["./build.sh"]
