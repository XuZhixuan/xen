FROM amd64/debian:unstable
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive
ENV QEMU_VERSION=8.2.0-rc2
ENV USER root

RUN mkdir /build
WORKDIR /build

# build depends
RUN apt-get update && \
    apt-get --quiet --yes install \
        build-essential \
        curl \
        python3 \
        python3-pip \
        python3-elementpath \
        ninja-build \
        pkg-config \
        libglib2.0-dev \
        libpixman-1-dev \
        && \
    \
    curl -fsSLO https://download.qemu.org/qemu-"$QEMU_VERSION".tar.xz && \
    tar xvJf qemu-"$QEMU_VERSION".tar.xz && \
    cd qemu-"$QEMU_VERSION" && \
    ./configure                \
        --target-list=riscv64-softmmu \
        --enable-system        \
        --disable-bsd-user     \
        --disable-debug-info   \
        --disable-glusterfs    \
        --disable-gtk          \
        --disable-guest-agent  \
        --disable-linux-user   \
        --disable-sdl          \
        --disable-spice        \
        --disable-tpm          \
        --disable-vhost-net    \
        --disable-vhost-user   \
        --disable-virtfs       \
        --disable-vnc          \
        --disable-werror       \
        --disable-xen          \
        --disable-safe-stack   \
        --disable-libssh       \
        --disable-opengl       \
        --disable-tools        \
        --disable-virglrenderer  \
        --disable-stack-protector  \
        --disable-containers   \
        --disable-replication  \
        --disable-cloop        \
        --disable-dmg          \
        --disable-vvfat        \
        --disable-vdi          \
        --disable-parallels    \
        --disable-qed          \
        --disable-bochs        \
        --disable-qom-cast-debug  \
        --disable-vhost-vdpa   \
        --disable-vhost-kernel \
        --disable-qcow1        \
        --disable-live-block-migration \
    && \
    make -j$(nproc) && \
    cp ./build/qemu-system-riscv64 / && \
    cp ./pc-bios/opensbi-riscv64-generic-fw_dynamic.bin  / && \
    cd /build && \
    rm -rf qemu-"$QEMU_VERSION"* && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*

