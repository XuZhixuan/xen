FROM --platform=linux/amd64 archlinux
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

# Packages needed for the build
RUN pacman --noconfirm --needed -Syu \
    base-devel \
    riscv64-linux-gnu-gcc \
    git \
    bc

# Add compiler path
ENV CROSS_COMPILE=riscv64-linux-gnu-

USER root
WORKDIR /build

ARG ARCH=riscv

RUN \
    git clone --branch riscv_aia_v10 --depth 1 --single-branch https://github.com/avpatel/linux.git && \
    cd linux && \
    echo 'From dace965b74e3d6988d32820e5e51c2496751dd8a Mon Sep 17 00:00:00 2001' > fakedev.patch && \
    echo 'Message-ID: <dace965b74e3d6988d32820e5e51c2496751dd8a.1706115523.git.oleksii.kurochko@gmail.com>' >> fakedev.patch && \
    echo 'From: Oleksii Kurochko <oleksii.kurochko@gmail.com>' >> fakedev.patch && \
    echo 'Date: Wed, 24 Jan 2024 18:56:53 +0200' >> fakedev.patch && \
    echo 'Subject: [PATCH] riscv: add fakedev driver' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    echo 'The patch adds a driver for a device to test that passthrough' >> fakedev.patch && \
    echo 'is working fine for the case of aplic, imsic virtualization.' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    echo 'To test that interrupts are recieved:' >> fakedev.patch && \
    echo 'From the guest, once you have the console you can trigger an interrupt using this command:' >> fakedev.patch && \
    echo 'There are two devices in case you want to test it with 2 domUs, one device per dom.' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    echo 'Device with address e000000' >> fakedev.patch && \
    echo 'echo 0 > /sys/devices/platform/passthrough/e000000.fakedev-irq/trigg for interrupt 12' >> fakedev.patch && \
    echo 'echo 1 > /sys/devices/platform/passthrough/e000000.fakedev-irq/trigg for interrupt 13' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    echo 'Device with address e001000' >> fakedev.patch && \
    echo 'echo 0 > /sys/devices/platform/passthrough/e000000.fakedev-irq/trigg for interrupt 14' >> fakedev.patch && \
    echo 'echo 1 > /sys/devices/platform/passthrough/e000000.fakedev-irq/trigg for interrupt 15' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    echo 'in the guest passthrough DTS add this node' >> fakedev.patch && \
    echo 'fakedev-irq@e000000 {' >> fakedev.patch && \
    echo '  compatible = "mchp,fakedev-irq";' >> fakedev.patch && \
    echo '  reg = <0x0 0xe000000 0x0 0x1000>;' >> fakedev.patch && \
    echo '  interrupt-parent = <&gic>;' >> fakedev.patch && \
    echo '  interrupts = <12 4 13 4>;' >> fakedev.patch && \
    echo '  xen,reg = <0x0 0xe000000 0x0 0x1000 0x0 0xe000000>;' >> fakedev.patch && \
    echo '  xen,force-assign-without-iommu;' >> fakedev.patch && \
    echo '};' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    echo 'Or' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    echo 'fakedev-irq@e001000 {' >> fakedev.patch && \
    echo '  compatible = "mchp,fakedev-irq";' >> fakedev.patch && \
    echo '  reg = <0x0 0xe001000 0x0 0x1000>;' >> fakedev.patch && \
    echo '  interrupt-parent = <&gic>;' >> fakedev.patch && \
    echo '  interrupts = <14 4 15 4>;' >> fakedev.patch && \
    echo '  xen,reg = <0x0 0xe001000 0x0 0x1000 0x0 0xe001000>;' >> fakedev.patch && \
    echo '  xen,force-assign-without-iommu;' >> fakedev.patch && \
    echo '};' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    echo 'Signed-off-by: Oleksii Kurochko <oleksii.kurochko@gmail.com>' >> fakedev.patch && \
    echo '---' >> fakedev.patch && \
    echo ' drivers/misc/Makefile      |   1 +' >> fakedev.patch && \
    echo ' drivers/misc/fakedev-irq.c | 129 +++++++++++++++++++++++++++++++++++++' >> fakedev.patch && \
    echo ' 2 files changed, 130 insertions(+)' >> fakedev.patch && \
    echo ' create mode 100644 drivers/misc/fakedev-irq.c' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    echo 'diff --git a/drivers/misc/Makefile b/drivers/misc/Makefile' >> fakedev.patch && \
    echo 'index f2a4d1ff6..73d7ebe9e 100644' >> fakedev.patch && \
    echo '--- a/drivers/misc/Makefile' >> fakedev.patch && \
    echo '+++ b/drivers/misc/Makefile' >> fakedev.patch && \
    echo '@@ -67,3 +67,4 @@ obj-$(CONFIG_TMR_MANAGER)      += xilinx_tmr_manager.o' >> fakedev.patch && \
    echo ' obj-$(CONFIG_TMR_INJECT)	+= xilinx_tmr_inject.o' >> fakedev.patch && \
    echo ' obj-$(CONFIG_TPS6594_ESM)	+= tps6594-esm.o' >> fakedev.patch && \
    echo ' obj-$(CONFIG_TPS6594_PFSM)	+= tps6594-pfsm.o' >> fakedev.patch && \
    echo '+obj-y += fakedev-irq.o' >> fakedev.patch && \
    echo 'diff --git a/drivers/misc/fakedev-irq.c b/drivers/misc/fakedev-irq.c' >> fakedev.patch && \
    echo 'new file mode 100644' >> fakedev.patch && \
    echo 'index 000000000..abf7d3f01' >> fakedev.patch && \
    echo '--- /dev/null' >> fakedev.patch && \
    echo '+++ b/drivers/misc/fakedev-irq.c' >> fakedev.patch && \
    echo '@@ -0,0 +1,129 @@' >> fakedev.patch && \
    echo '+#include <linux/err.h>' >> fakedev.patch && \
    echo '+#include <linux/io.h>' >> fakedev.patch && \
    echo '+#include <linux/interrupt.h>' >> fakedev.patch && \
    echo '+#include <linux/kernel.h>' >> fakedev.patch && \
    echo '+#include <linux/module.h>' >> fakedev.patch && \
    echo '+#include <linux/of.h>' >> fakedev.patch && \
    echo '+#include <linux/platform_device.h>' >> fakedev.patch && \
    echo '+#include <linux/slab.h>' >> fakedev.patch && \
    echo '+#include <linux/sysfs.h>' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+/* Register map */' >> fakedev.patch && \
    echo '+#define REG_IRQ_ENABLE 0x0' >> fakedev.patch && \
    echo '+#define REG_IRQ_TRIGG  0x4' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+struct fakedev {' >> fakedev.patch && \
    echo '+    struct device *dev;' >> fakedev.patch && \
    echo '+    void __iomem *base;' >> fakedev.patch && \
    echo '+};' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static ssize_t fakedev_irq_show_enabled(struct device *dev,' >> fakedev.patch && \
    echo '+              struct device_attribute *attr, char *buf)' >> fakedev.patch && \
    echo '+{' >> fakedev.patch && \
    echo '+    struct fakedev *dt = dev_get_drvdata(dev);' >> fakedev.patch && \
    echo '+    uint32_t val = readl_relaxed(dt->base + REG_IRQ_ENABLE);' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    return scnprintf(buf, PAGE_SIZE, "IRQs bitmap: 0x%04x\n", val);' >> fakedev.patch && \
    echo '+}' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static ssize_t fakedev_irq_store_trigg(struct device *dev,' >> fakedev.patch && \
    echo '+                struct device_attribute *attr,' >> fakedev.patch && \
    echo '+                const char *buf, size_t len)' >> fakedev.patch && \
    echo '+{' >> fakedev.patch && \
    echo '+    struct fakedev *dt = dev_get_drvdata(dev);' >> fakedev.patch && \
    echo '+    unsigned long val;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    if (kstrtoul(buf, 0, &val))' >> fakedev.patch && \
    echo '+        return -EINVAL;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    printk("AAAAAAAAA\n");' >> fakedev.patch && \
    echo '+    writel_relaxed((uint32_t)val, dt->base + REG_IRQ_TRIGG);' >> fakedev.patch && \
    echo '+    return len;' >> fakedev.patch && \
    echo '+}' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static DEVICE_ATTR(enabled, S_IRUGO, fakedev_irq_show_enabled, NULL);' >> fakedev.patch && \
    echo '+static DEVICE_ATTR(trigg, S_IRUGO | S_IWUSR, NULL, fakedev_irq_store_trigg);' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static struct attribute *fakedev_irq_attributes[] = {' >> fakedev.patch && \
    echo '+    &dev_attr_enabled.attr,' >> fakedev.patch && \
    echo '+    &dev_attr_trigg.attr,' >> fakedev.patch && \
    echo '+    NULL,' >> fakedev.patch && \
    echo '+};' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static const struct attribute_group fakedev_irq_attr_group = {' >> fakedev.patch && \
    echo '+    .attrs = fakedev_irq_attributes,' >> fakedev.patch && \
    echo '+};' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static irqreturn_t fakedev_irq_irq_handler(int irq, void *data)' >> fakedev.patch && \
    echo '+{' >> fakedev.patch && \
    echo '+    return IRQ_HANDLED;' >> fakedev.patch && \
    echo '+}' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static int fakedev_irq_probe(struct platform_device *pdev)' >> fakedev.patch && \
    echo '+{' >> fakedev.patch && \
    echo '+    struct device *dev = &pdev->dev;' >> fakedev.patch && \
    echo '+    struct resource *res;' >> fakedev.patch && \
    echo '+    struct fakedev *dt;' >> fakedev.patch && \
    echo '+    int ret, irq, res_num = 0;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);' >> fakedev.patch && \
    echo '+    if (!res)' >> fakedev.patch && \
    echo '+        return -ENOMEM;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    dt = devm_kzalloc(dev, sizeof(*dt), GFP_KERNEL);' >> fakedev.patch && \
    echo '+    if (!dt)' >> fakedev.patch && \
    echo '+        return -ENOMEM;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    dt->dev = dev;' >> fakedev.patch && \
    echo '+    dt->base = devm_ioremap(dev, res->start, resource_size(res));' >> fakedev.patch && \
    echo '+    if (!dt->base)' >> fakedev.patch && \
    echo '+        return -EINVAL;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    while ((irq = platform_get_irq_optional(pdev, res_num)) != -ENXIO) {' >> fakedev.patch && \
    echo '+        uint32_t reg_val;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+        if (irq < 0)' >> fakedev.patch && \
    echo '+            return irq;' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+        ret = devm_request_irq(dev, irq, fakedev_irq_irq_handler, IRQF_TRIGGER_HIGH, "fakedev-irq", dt);' >> fakedev.patch && \
    echo '+        if (ret) {' >> fakedev.patch && \
    echo '+            dev_err(dev, "request_irq() failed\n");' >> fakedev.patch && \
    echo '+            return ret;' >> fakedev.patch && \
    echo '+        }' >> fakedev.patch && \
    echo '+        reg_val = readl_relaxed(dt->base + REG_IRQ_ENABLE);' >> fakedev.patch && \
    echo '+        writel_relaxed(reg_val | (1 << res_num), dt->base + REG_IRQ_ENABLE);' >> fakedev.patch && \
    echo '+        dev_info(dt->dev, "interrupt %u enabled\n", irq);' >> fakedev.patch && \
    echo '+        res_num++;' >> fakedev.patch && \
    echo '+    }' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    platform_set_drvdata(pdev, dt);' >> fakedev.patch && \
    echo '+    return sysfs_create_group(&dev->kobj, &fakedev_irq_attr_group);' >> fakedev.patch && \
    echo '+}' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static int fakedev_irq_remove(struct platform_device *pdev)' >> fakedev.patch && \
    echo '+{' >> fakedev.patch && \
    echo '+    struct fakedev *dt = platform_get_drvdata(pdev);' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+    sysfs_remove_group(&dt->dev->kobj, &fakedev_irq_attr_group);' >> fakedev.patch && \
    echo '+    return 0;' >> fakedev.patch && \
    echo '+}' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static const struct of_device_id fakedev_irq_of_match[] = {' >> fakedev.patch && \
    echo '+    { .compatible = "mchp,fakedev-irq", },' >> fakedev.patch && \
    echo '+    { }' >> fakedev.patch && \
    echo '+};' >> fakedev.patch && \
    echo '+MODULE_DEVICE_TABLE(of, fakedev_irq_of_match);' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+static struct platform_driver fakedev_irq_driver = {' >> fakedev.patch && \
    echo '+    .probe = fakedev_irq_probe,' >> fakedev.patch && \
    echo '+    .remove = fakedev_irq_remove,' >> fakedev.patch && \
    echo '+    .driver = {' >> fakedev.patch && \
    echo '+        .name = "fakedev-irq",' >> fakedev.patch && \
    echo '+        .of_match_table = fakedev_irq_of_match,' >> fakedev.patch && \
    echo '+    },' >> fakedev.patch && \
    echo '+};' >> fakedev.patch && \
    echo '+module_platform_driver(fakedev_irq_driver);' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '+MODULE_DESCRIPTION("Fake Device Interrupts Test Driver");' >> fakedev.patch && \
    echo '+MODULE_LICENSE("GPL");' >> fakedev.patch && \
    echo '+' >> fakedev.patch && \
    echo '-- ' >> fakedev.patch && \
    echo '2.43.0' >> fakedev.patch && \
    echo '' >> fakedev.patch && \
    git apply fakedev.patch  && \
    make ARCH=$ARCH defconfig && \
    sed "/CONFIG_BLK_DEV_RAM\b/s/.*/CONFIG_BLK_DEV_RAM=y/" -i .config && \
    sed "/CONFIG_RISCV_SBI_V01\b/s/.*/CONFIG_RISCV_SBI_V01=y/" -i .config && \
    echo "CONFIG_HVC_RISCV_SBI=y" >> .config && \
    echo "CONFIG_SERIAL_EARLYCON_RISCV_SBI=y" >> .config && \
    echo "CONFIG_BLK_DEV_RAM_COUNT=16" >> .config && \
    echo "CONFIG_BLK_DEV_RAM_SIZE=2147483648" >> .config && \
    make ARCH=$ARCH -j$(nproc) Image.gz  && \
    cp arch/$ARCH/boot/Image.gz /

RUN \
    rm -rf linux

