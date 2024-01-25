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
    echo 'From a171498867f83b37898aab7ab483c23bafd22290 Mon Sep 17 00:00:00 2001' >> fakedev.patch && \
    echo 'Message-ID: <a171498867f83b37898aab7ab483c23bafd22290.1706179900.git.oleksii.kurochko@gmail.com>' >> fakedev.patch && \
    echo 'From: Oleksii Kurochko <oleksii.kurochko@gmail.com>' >> fakedev.patch && \
    echo 'Date: Fri, 19 Jan 2024 14:48:23 +0200' >> fakedev.patch && \
    echo 'Subject: [PATCH] qemu/riscv: add fakedev device for testing' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    echo 'Signed-off-by: Oleksii Kurochko <oleksii.kurochko@gmail.com>' >> fakedev.patch && \
    echo '---' >> fakedev.patch && \
    echo ' hw/misc/Kconfig               |   3 +' >> fakedev.patch && \
    echo ' hw/misc/fakedev-irq.c         | 104 ++++++++++++++++++++++++++++++++++' >> fakedev.patch && \
    echo ' hw/misc/meson.build           |   3 +' >> fakedev.patch && \
    echo ' hw/riscv/Kconfig              |   1 +' >> fakedev.patch && \
    echo ' hw/riscv/virt.c               |  13 +++++' >> fakedev.patch && \
    echo ' include/hw/misc/fakedev-irq.h |  28 +++++++++' >> fakedev.patch && \
    echo ' include/hw/riscv/virt.h       |   4 +-' >> fakedev.patch && \
    echo ' 7 files changed, 155 insertions(+), 1 deletion(-)' >> fakedev.patch && \
    echo ' create mode 100644 hw/misc/fakedev-irq.c' >> fakedev.patch && \
    echo ' create mode 100644 include/hw/misc/fakedev-irq.h' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    echo 'diff --git a/hw/misc/Kconfig b/hw/misc/Kconfig' >> fakedev.patch && \
    echo 'index cc8a8c1418..cfbc720633 100644' >> fakedev.patch && \
    echo '--- a/hw/misc/Kconfig' >> fakedev.patch && \
    echo '+++ b/hw/misc/Kconfig' >> fakedev.patch && \
    echo '@@ -200,4 +200,7 @@ config IOSB' >> fakedev.patch && \
    echo ' config XLNX_VERSAL_TRNG' >> fakedev.patch && \
    echo '     bool' >> fakedev.patch && \
    echo ' ' >> fakedev.patch && \
    echo '+config FAKEDEV_IRQ' >> fakedev.patch && \
    echo '+    bool' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo ' source macio/Kconfig' >> fakedev.patch && \
    echo 'diff --git a/hw/misc/fakedev-irq.c b/hw/misc/fakedev-irq.c' >> fakedev.patch && \
    echo 'new file mode 100644' >> fakedev.patch && \
    echo 'index 0000000000..2db9a60ea8' >> fakedev.patch && \
    echo '--- /dev/null' >> fakedev.patch && \
    echo '+++ b/hw/misc/fakedev-irq.c' >> fakedev.patch && \
    echo '@@ -0,0 +1,104 @@' >> fakedev.patch && \
    echo '+#include "qemu/osdep.h"' >> fakedev.patch && \
    echo '+#include "hw/hw.h"' >> fakedev.patch && \
    echo '+#include "hw/irq.h"' >> fakedev.patch && \
    echo '+#include "hw/sysbus.h"' >> fakedev.patch && \
    echo '+#include "qemu/bitops.h"' >> fakedev.patch && \
    echo '+#include "qemu/log.h"' >> fakedev.patch && \
    echo '+#include "qapi/error.h"' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+#include "hw/misc/fakedev-irq.h"' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static uint64_t fakedev_irq_read(void *opaque, hwaddr offset, unsigned size)' >> fakedev.patch && \
    echo '+{' >> fakedev.patch && \
    echo '+    FakeDevIrqState *s = (FakeDevIrqState *)opaque;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    if(size != sizeof(uint32_t)) {' >> fakedev.patch && \
    echo '+        fprintf(stderr, "wrong read access size %u\\n", size);' >> fakedev.patch && \
    echo '+        return ~(0ULL);' >> fakedev.patch && \
    echo '+    }' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    switch (offset) {' >> fakedev.patch && \
    echo '+        case REG_IRQ_ENABLE:' >> fakedev.patch && \
    echo '+            return s->enabled;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+        default:' >> fakedev.patch && \
    echo '+            break;' >> fakedev.patch && \
    echo '+    }' >> fakedev.patch && \
    echo '+    return ~(0ULL);' >> fakedev.patch && \
    echo '+}' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static void fakedev_irq_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)' >> fakedev.patch && \
    echo '+{' >> fakedev.patch && \
    echo '+    FakeDevIrqState *s = (FakeDevIrqState *)opaque;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    if(size == sizeof(uint32_t)) {' >> fakedev.patch && \
    echo '+        switch (offset) {' >> fakedev.patch && \
    echo '+            case REG_IRQ_TRIGG:' >> fakedev.patch && \
    echo '+                if (value < FAKEDEV_NB_IRQS) {' >> fakedev.patch && \
    echo '+                    if((s->enabled & (1 << value))) {' >> fakedev.patch && \
    echo '+                        qemu_irq_pulse(s->irqs[value]);' >> fakedev.patch && \
    echo '+                    }' >> fakedev.patch && \
    echo '+                }' >> fakedev.patch && \
    echo '+                break;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+            case REG_IRQ_ENABLE:' >> fakedev.patch && \
    echo '+                    s->enabled = value;' >> fakedev.patch && \
    echo '+                break;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+            default:' >> fakedev.patch && \
    echo '+                fprintf(stderr, "wrong register access at offset 0x%lx\\n", offset);' >> fakedev.patch && \
    echo '+                break;' >> fakedev.patch && \
    echo '+        }' >> fakedev.patch && \
    echo '+    } else {' >> fakedev.patch && \
    echo '+        fprintf(stderr, "wrong write access size %u\\n", size);' >> fakedev.patch && \
    echo '+    }' >> fakedev.patch && \
    echo '+}' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static const MemoryRegionOps fakedev_irq_ops = {' >> fakedev.patch && \
    echo '+    .read = fakedev_irq_read,' >> fakedev.patch && \
    echo '+    .write = fakedev_irq_write,' >> fakedev.patch && \
    echo '+    .endianness = DEVICE_NATIVE_ENDIAN,' >> fakedev.patch && \
    echo '+    .impl = {' >> fakedev.patch && \
    echo '+        .min_access_size = 4,' >> fakedev.patch && \
    echo '+        .max_access_size = 4,' >> fakedev.patch && \
    echo '+    },' >> fakedev.patch && \
    echo '+    .valid = {' >> fakedev.patch && \
    echo '+        .min_access_size = 4,' >> fakedev.patch && \
    echo '+        .max_access_size = 4,' >> fakedev.patch && \
    echo '+    }' >> fakedev.patch && \
    echo '+};' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static void fakedev_irq_init(Object *obj)' >> fakedev.patch && \
    echo '+{' >> fakedev.patch && \
    echo '+    FakeDevIrqState *s = FAKEDEV_IRQ(obj);' >> fakedev.patch && \
    echo '+    SysBusDevice    *d = SYS_BUS_DEVICE(obj);' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    memory_region_init_io(&s->regs, obj, &fakedev_irq_ops, s,' >> fakedev.patch && \
    echo '+                          FAKEDEV_IRQ_NAME, FAKEDEV_IRQ_REG_SIZE);' >> fakedev.patch && \
    echo '+    sysbus_init_mmio(d, &s->regs);' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    for(int i =0; i < FAKEDEV_NB_IRQS; i++)' >> fakedev.patch && \
    echo '+        sysbus_init_irq(d, &s->irqs[i]);' >> fakedev.patch && \
    echo '+}' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static void fakedev_irq_class_init(ObjectClass *klass, void *data)' >> fakedev.patch && \
    echo '+{' >> fakedev.patch && \
    echo '+    DeviceClass *dc = DEVICE_CLASS(klass);' >> fakedev.patch && \
    echo '+    dc->desc = FAKEDEV_IRQ_NAME;' >> fakedev.patch && \
    echo '+}' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static const TypeInfo fakedev_irq_info = {' >> fakedev.patch && \
    echo '+    .name = FAKEDEV_IRQ_NAME,' >> fakedev.patch && \
    echo '+    .parent = TYPE_SYS_BUS_DEVICE,' >> fakedev.patch && \
    echo '+    .instance_size = sizeof(FakeDevIrqState),' >> fakedev.patch && \
    echo '+    .instance_init = fakedev_irq_init,' >> fakedev.patch && \
    echo '+    .class_init = fakedev_irq_class_init,' >> fakedev.patch && \
    echo '+};' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static void fakedev_irq_register_types(void)' >> fakedev.patch && \
    echo '+{' >> fakedev.patch && \
    echo '+    type_register_static(&fakedev_irq_info);' >> fakedev.patch && \
    echo '+}' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+type_init(fakedev_irq_register_types)' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo 'diff --git a/hw/misc/meson.build b/hw/misc/meson.build' >> fakedev.patch && \
    echo 'index 36c20d5637..c2629b1ab5 100644' >> fakedev.patch && \
    echo '--- a/hw/misc/meson.build' >> fakedev.patch && \
    echo '+++ b/hw/misc/meson.build' >> fakedev.patch && \
    echo "@@ -154,3 +154,6 @@ system_ss.add(when: 'CONFIG_SBSA_REF', if_true: files('sbsa_ec.c'))" >> fakedev.patch && \
    echo ' ' >> fakedev.patch && \
    echo ' # HPPA devices' >> fakedev.patch && \
    echo " system_ss.add(when: 'CONFIG_LASI', if_true: files('lasi.c'))" >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+# Fakedev-irq device' >> fakedev.patch && \
    echo "+system_ss.add(when: 'CONFIG_FAKEDEV_IRQ', if_true: files('fakedev-irq.c'))" >> fakedev.patch && \
    echo 'diff --git a/hw/riscv/Kconfig b/hw/riscv/Kconfig' >> fakedev.patch && \
    echo 'index b6a5eb4452..b67e805990 100644' >> fakedev.patch && \
    echo '--- a/hw/riscv/Kconfig' >> fakedev.patch && \
    echo '+++ b/hw/riscv/Kconfig' >> fakedev.patch && \
    echo '@@ -45,6 +45,7 @@ config RISCV_VIRT' >> fakedev.patch && \
    echo '     select FW_CFG_DMA' >> fakedev.patch && \
    echo '     select PLATFORM_BUS' >> fakedev.patch && \
    echo '     select ACPI' >> fakedev.patch && \
    echo '+    select FAKEDEV_IRQ' >> fakedev.patch && \
    echo ' ' >> fakedev.patch && \
    echo ' config SHAKTI_C' >> fakedev.patch && \
    echo '     bool' >> fakedev.patch && \
    echo 'diff --git a/hw/riscv/virt.c b/hw/riscv/virt.c' >> fakedev.patch && \
    echo 'index d2eac24156..458a15b194 100644' >> fakedev.patch && \
    echo '--- a/hw/riscv/virt.c' >> fakedev.patch && \
    echo '+++ b/hw/riscv/virt.c' >> fakedev.patch && \
    echo '@@ -53,6 +53,7 @@' >> fakedev.patch && \
    echo ' #include "hw/display/ramfb.h"' >> fakedev.patch && \
    echo ' #include "hw/acpi/aml-build.h"' >> fakedev.patch && \
    echo ' #include "qapi/qapi-visit-common.h"' >> fakedev.patch && \
    echo '+#include "hw/misc/fakedev-irq.h"' >> fakedev.patch && \
    echo ' ' >> fakedev.patch && \
    echo ' /*' >> fakedev.patch && \
    echo '  * The virt machine physical address space used by some of the devices' >> fakedev.patch && \
    echo '@@ -103,6 +104,8 @@ static const MemMapEntry virt_memmap[] = {' >> fakedev.patch && \
    echo '     [VIRT_PCIE_ECAM] =    { 0x30000000,    0x10000000 },' >> fakedev.patch && \
    echo '     [VIRT_PCIE_MMIO] =    { 0x40000000,    0x40000000 },' >> fakedev.patch && \
    echo '     [VIRT_DRAM] =         { 0x80000000,           0x0 },' >> fakedev.patch && \
    echo '+    [VIRT_FAKEDEV1_IRQ] =  { FAKEDEV1_IRQ_BASE, FAKEDEV_IRQ_REG_SIZE },' >> fakedev.patch && \
    echo '+    [VIRT_FAKEDEV2_IRQ] =  { FAKEDEV2_IRQ_BASE, FAKEDEV_IRQ_REG_SIZE },' >> fakedev.patch && \
    echo ' };' >> fakedev.patch && \
    echo ' ' >> fakedev.patch && \
    echo ' /* PCIe high mmio is fixed for RV32 */' >> fakedev.patch && \
    echo '@@ -1543,6 +1546,16 @@ static void virt_machine_init(MachineState *machine)' >> fakedev.patch && \
    echo '     }' >> fakedev.patch && \
    echo '     virt_flash_map(s, system_memory);' >> fakedev.patch && \
    echo ' ' >> fakedev.patch && \
    echo '+    sysbus_create_varargs(FAKEDEV_IRQ_NAME, FAKEDEV1_IRQ_BASE,' >> fakedev.patch && \
    echo '+                         qdev_get_gpio_in(mmio_irqchip, 12),' >> fakedev.patch && \
    echo '+                         qdev_get_gpio_in(mmio_irqchip, 13),' >> fakedev.patch && \
    echo '+                         NULL);' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    sysbus_create_varargs(FAKEDEV_IRQ_NAME, FAKEDEV2_IRQ_BASE,' >> fakedev.patch && \
    echo '+                         qdev_get_gpio_in(mmio_irqchip, 14),' >> fakedev.patch && \
    echo '+                         qdev_get_gpio_in(mmio_irqchip, 15),' >> fakedev.patch && \
    echo '+                         NULL);' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '     /* load/create device tree */' >> fakedev.patch && \
    echo '     if (machine->dtb) {' >> fakedev.patch && \
    echo '         machine->fdt = load_device_tree(machine->dtb, &s->fdt_size);' >> fakedev.patch && \
    echo 'diff --git a/include/hw/misc/fakedev-irq.h b/include/hw/misc/fakedev-irq.h' >> fakedev.patch && \
    echo 'new file mode 100644' >> fakedev.patch && \
    echo 'index 0000000000..d6029e9f04' >> fakedev.patch && \
    echo '--- /dev/null' >> fakedev.patch && \
    echo '+++ b/include/hw/misc/fakedev-irq.h' >> fakedev.patch && \
    echo '@@ -0,0 +1,28 @@' >> fakedev.patch && \
    echo '+#define FAKEDEV_NB_IRQS 2' >> fakedev.patch && \
    echo '+#define FAKEDEV_IRQ_BASE 12' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+#define FAKEDEV_IRQ_REG_BASE   0xe000000' >> fakedev.patch && \
    echo '+#define FAKEDEV_IRQ_REG_SIZE   0x1000' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+#define CREATE_DEV(id) (FAKEDEV_IRQ_REG_BASE + FAKEDEV_IRQ_REG_SIZE*id)' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+#define FAKEDEV1_IRQ_BASE       CREATE_DEV(0)' >> fakedev.patch && \
    echo '+#define FAKEDEV2_IRQ_BASE      CREATE_DEV(1)' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+#define FAKEDEV_IRQ_NAME  "fakedev-irq"' >> fakedev.patch && \
    echo '+#define FAKEDEV_IRQ(obj)  OBJECT_CHECK(FakeDevIrqState,(obj),FAKEDEV_IRQ_NAME)' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+/* Register map */' >> fakedev.patch && \
    echo '+#define REG_IRQ_ENABLE 0x0' >> fakedev.patch && \
    echo '+#define REG_IRQ_TRIGG  0x4' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+typedef struct' >> fakedev.patch && \
    echo '+{' >> fakedev.patch && \
    echo '+    SysBusDevice     parent_obj;' >> fakedev.patch && \
    echo '+    MemoryRegion     regs;' >> fakedev.patch && \
    echo '+    qemu_irq         irqs[FAKEDEV_NB_IRQS];' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    uint32_t enabled;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+} FakeDevIrqState;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo 'diff --git a/include/hw/riscv/virt.h b/include/hw/riscv/virt.h' >> fakedev.patch && \
    echo 'index e5c474b26e..fa0733e4d1 100644' >> fakedev.patch && \
    echo '--- a/include/hw/riscv/virt.h' >> fakedev.patch && \
    echo '+++ b/include/hw/riscv/virt.h' >> fakedev.patch && \
    echo '@@ -82,7 +82,9 @@ enum {' >> fakedev.patch && \
    echo '     VIRT_PCIE_MMIO,' >> fakedev.patch && \
    echo '     VIRT_PCIE_PIO,' >> fakedev.patch && \
    echo '     VIRT_PLATFORM_BUS,' >> fakedev.patch && \
    echo '-    VIRT_PCIE_ECAM' >> fakedev.patch && \
    echo '+    VIRT_PCIE_ECAM,' >> fakedev.patch && \
    echo '+    VIRT_FAKEDEV1_IRQ,' >> fakedev.patch && \
    echo '+    VIRT_FAKEDEV2_IRQ,' >> fakedev.patch && \
    echo ' };' >> fakedev.patch && \
    echo ' ' >> fakedev.patch && \
    echo ' enum {' >> fakedev.patch && \
    echo '-- ' >> fakedev.patch && \
    echo '2.43.0' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    patch -p1 < fakedev.patch && \
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
    && \
    rm -rf qemu-"$QEMU_VERSION"* && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*
