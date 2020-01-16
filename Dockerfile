FROM alpine:3.11.2

RUN mkdir -p /opt/ndff
ADD . /opt/ndff

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
    && cd /tmp \
    && git clone https://github.com/ntop/nDPI.git \
    && cd nDPI \
    && git checkout 98d9f524f9ff7746d0345939fe543020f8057212 \
    && ./autogen.sh \
    && ./configure \
    && make \
    && make install \
    && cd .. \
    && rm -rf nDPI \
    && cd /opt/ndff \
    && rm -rf build \
    && CC=clang CXX=clang++ meson build \
    && cd build && ninja \
    && ninja test \
    && ninja install \
    && apk del build-base \
    meson git autoconf automake make clang libtool pkgconfig ninja json-c-dev msgpack-c-dev gtest-dev libpcap-dev

CMD ["/bin/sh"]
