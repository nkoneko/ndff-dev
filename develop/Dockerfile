FROM debian:buster-slim

RUN mkdir -p /opt/ndff
ADD build.sh /opt/ndff

RUN apt update \
    && apt install -y \
    build-essential \
    meson \
    git \
    autoconf \
    automake \
    libtool \
    make \
    clang \
    pkg-config \
    ninja-build \
    libjson-c3 \
    libjson-c-dev \
    libmsgpackc2 \
    libmsgpack-dev \
    cmake \
    flex \
    bison \
    ragel \
    libboost-dev \
    python3-dev \
    inotify-tools \
    && rm -rf /var/cache/apk/* \
    && cd /tmp \
    && git clone https://github.com/the-tcpdump-group/libpcap \
    && cd libpcap \
    && git checkout -b 1.9.1 libpcap-1.9.1 \
    && mkdir build && cd build \
    && cmake .. && make && make install \
    && cd ../.. && rm -rf libpcap \
    && git clone https://github.com/intel/hyperscan \
    && cd hyperscan && git checkout -b 5.2.1 v5.2.1 && mkdir build && cd build \
    && cmake .. && make -j2 && ./bin/unit-hyperscan && make install \
    && cd /tmp && rm -rf hyperscan \
    && git clone https://github.com/ntop/nDPI.git \
    && cd nDPI \
    && git checkout -b 2.8-dev 98d9f524f9ff7746d0345939fe543020f8057212 \
    && ./autogen.sh \
    && ./configure \
    && make \
    && make install \
    && cd .. \
    && rm -rf nDPI \
    && git clone https://github.com/google/googletest \
    && cd googletest && git checkout -b 1.10 release-1.10.0 \
    && mkdir build && cd build && cmake .. \
    && make && make install \
    && cd /tmp && rm -rf googletest \
    && apt remove -y --purge flex bison autoconf automake libtool make git

WORKDIR /opt/ndff
CMD ["./build.sh"]
