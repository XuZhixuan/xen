obj-y += cpufeature.o
obj-y += delay.o
obj-y += device.o
obj-y += domain.o
obj-y += domain_build.o
obj-y += domctl.o
obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
obj-y += efi/
obj-y += entry.o
obj-y += guestcopy.o
obj-y += irq.o
obj-y += kernel.o
obj-y += lib/
obj-y += mm.o
obj-y += percpu.o
obj-y += p2m.o
obj-y += plic.o
obj-$(CONFIG_RISCV_64) += riscv64/
obj-y += sbi.o
obj-y += setup.o
obj-y += shutdown.o
obj-y += smp.o
obj-y += smpboot.o
obj-y += sysctl.o
obj-y += time.o
obj-y += traps.o
obj-y += uart.o
obj-y += vm_event.o
obj-y += vplic.o
obj-y += vtimer.o
obj-y += vsbi_uart.o

$(TARGET): $(TARGET)-syms
	$(OBJCOPY) -O binary -S $< $@

$(TARGET)-syms: $(objtree)/prelink.o $(obj)/xen.lds
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< \
	    $(objtree)/common/symbols-dummy.o -o $(@D)/.$(@F).0
	$(NM) -pa --format=sysv $(@D)/.$(@F).0 \
		| $(objtree)/tools/symbols $(all_symbols) --sysv --sort >$(@D)/.$(@F).0.S
	$(MAKE) $(build)=$(@D) $(@D)/.$(@F).0.o
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< \
	    $(@D)/.$(@F).0.o -o $(@D)/.$(@F).1
	$(NM) -pa --format=sysv $(@D)/.$(@F).1 \
		| $(objtree)/tools/symbols $(all_symbols) --sysv --sort >$(@D)/.$(@F).1.S
	$(MAKE) $(build)=$(@D) $(@D)/.$(@F).1.o
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< $(build_id_linker) \
	    $(@D)/.$(@F).1.o -o $@
	$(NM) -pa --format=sysv $(@D)/$(@F) \
		| $(objtree)/tools/symbols --all-symbols --xensyms --sysv --sort \
		>$(@D)/$(@F).map
	rm -f $(@D)/.$(@F).[0-9]*

$(obj)/xen.lds: $(src)/xen.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

.PHONY: include
include:
