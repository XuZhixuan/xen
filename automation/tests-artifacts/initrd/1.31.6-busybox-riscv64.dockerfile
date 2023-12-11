FROM --platform=linux/amd64 archlinux
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

# Packages needed for the build
RUN pacman --noconfirm --needed -Syu \
    base-devel \
    riscv64-linux-gnu-gcc

# Add compiler path
ENV CROSS_COMPILE=riscv64-linux-gnu-

WORKDIR /build

ARG GENEXT2FS_DIR=genext2fs
ARG BUSYBOX_DIR=busybox
ARG INITRD_DIR=$WORK_DIR/initrd
ARG RCS_FILE=$WORK_DIR/rcS

ARG GENEXT2FS_VER=1.5.0
ARG BUSYBOX_VER=1.36.1

RUN \
    mkdir -p $GENEXT2FS_DIR && \
    curl -fsSLO https://github.com/bestouff/genext2fs/archive/v$GENEXT2FS_VER.tar.gz && \
    tar -xf v$GENEXT2FS_VER.tar.gz -C $GENEXT2FS_DIR --strip-components=1 && \
    cd $GENEXT2FS_DIR && \
    ./autogen.sh && \
    ./configure && \
    make && \
    make install

RUN \
    mkdir -p $BUSYBOX_DIR && \
    curl -fsSLO https://busybox.net/downloads/busybox-$BUSYBOX_VER.tar.bz2 && \
    tar -xf busybox-$BUSYBOX_VER.tar.bz2 -C $BUSYBOX_DIR --strip-components=1 && \
    cd $BUSYBOX_DIR && \
    make defconfig && \
    sed "/CONFIG_STATIC\b/s/.*/CONFIG_STATIC=y/" -i .config && \
    make -j$(grep -c '^processor' /proc/cpuinfo) && \
    make install CONFIG_PREFIX=$INITRD_DIR

RUN \
    echo -e "echo \"Hello RISC-V World!\"\nmount -t proc proc /proc\nmount -t sysfs sysfs /sys\n/bin/sh" > $RCS_FILE && \
    chmod +x $RCS_FILE && \
    mkdir -p $INITRD_DIR/etc/init.d && \
    cp $RCS_FILE $INITRD_DIR/etc/init.d && \
    mkdir -p $INITRD_DIR/proc && \
    mkdir -p $INITRD_DIR/sys && \
    genext2fs -b 6500 -N 1024 -U -d $INITRD_DIR /initrd.img # can be 3500

RUN \
    rm -rf busybox* initrd genext2fs* rcS  v$GENEXT2FS_VER.tar.gz

