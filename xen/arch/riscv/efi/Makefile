include $(srctree)/common/efi/efi-common.mk

ifeq ($(CONFIG_ARM_EFI),y)
$(error need to be implemented)
else
obj-y += common-stub.o

$(obj)/common-stub.o: CFLAGS-y += -fno-short-wchar

endif
