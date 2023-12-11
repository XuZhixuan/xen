FROM --platform=linux/amd64 archlinux
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

# Packages needed for the build
RUN pacman --noconfirm --needed -Syu \
    base-devel \
    riscv64-linux-gnu-gcc \
    bc

# Add compiler path
ENV CROSS_COMPILE=riscv64-linux-gnu-

USER root
WORKDIR /build

ARG LINUX_VERSION=6.4
ARG ARCH=riscv

RUN \
    curl -fsSLO https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-"$LINUX_VERSION".tar.xz && \
    tar xvJf linux-"$LINUX_VERSION".tar.xz && \
    cd linux-"$LINUX_VERSION" && \
    make ARCH=$ARCH defconfig && \
    sed "/CONFIG_BLK_DEV_RAM\b/s/.*/CONFIG_BLK_DEV_RAM=y/" -i .config && \
    sed "/CONFIG_RISCV_SBI_V01\b/s/.*/CONFIG_RISCV_SBI_V01=y/" -i .config && \
    echo "CONFIG_HVC_RISCV_SBI=y" >> .config && \
    echo "CONFIG_BLK_DEV_RAM_COUNT=16" >> .config && \
    echo "CONFIG_BLK_DEV_RAM_SIZE=2147483648" >> .config && \
    make ARCH=$ARCH -j$(nproc) Image.gz  && \
    cp arch/$ARCH/boot/Image.gz /

RUN \
    rm -rf linux-"$LINUX_VERSION"*

