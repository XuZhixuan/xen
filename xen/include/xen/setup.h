#ifndef __XEN_SETUP_H__
#define __XEN_SETUP_H__

#include <xen/init.h>
#include <xen/types.h>

#include <asm/setup.h>

#ifndef NR_MEM_BANKS
#define NR_MEM_BANKS 256
#endif

#ifndef MAX_MODULES
#define MAX_MODULES 32 /* Current maximum useful modules */
#endif

typedef enum {
    BOOTMOD_XEN,
    BOOTMOD_FDT,
    BOOTMOD_KERNEL,
    BOOTMOD_RAMDISK,
    BOOTMOD_XSM,
    BOOTMOD_GUEST_DTB,
    BOOTMOD_UNKNOWN
}  bootmodule_kind;

enum membank_type {
    /*
     * The MEMBANK_DEFAULT type refers to either reserved memory for the
     * device/firmware (when the bank is in 'reserved_mem') or any RAM (when
     * the bank is in 'mem').
     */
    MEMBANK_DEFAULT,
    /*
     * The MEMBANK_STATIC_DOMAIN type is used to indicate whether the memory
     * bank is bound to a static Xen domain. It is only valid when the bank
     * is in reserved_mem.
     */
    MEMBANK_STATIC_DOMAIN,
    /*
     * The MEMBANK_STATIC_HEAP type is used to indicate whether the memory
     * bank is reserved as static heap. It is only valid when the bank is
     * in reserved_mem.
     */
    MEMBANK_STATIC_HEAP,
};

/* Indicates the maximum number of characters(\0 included) for shm_id */
#define MAX_SHM_ID_LENGTH 16

struct membank {
    paddr_t start;
    paddr_t size;
    enum membank_type type;
#ifdef CONFIG_STATIC_SHM
    char shm_id[MAX_SHM_ID_LENGTH];
    unsigned int nr_shm_borrowers;
#endif
};

struct meminfo {
    unsigned int nr_banks;
    struct membank bank[NR_MEM_BANKS];
};

/*
 * The domU flag is set for kernels and ramdisks of "xen,domain" nodes.
 * The purpose of the domU flag is to avoid getting confused in
 * kernel_probe, where we try to guess which is the dom0 kernel and
 * initrd to be compatible with all versions of the multiboot spec. 
 */
#define BOOTMOD_MAX_CMDLINE 1024
struct bootmodule {
    bootmodule_kind kind;
    bool domU;
    paddr_t start;
    paddr_t size;
};

/* DT_MAX_NAME is the node name max length according the DT spec */
#define DT_MAX_NAME 41
struct bootcmdline {
    bootmodule_kind kind;
    bool domU;
    paddr_t start;
    char dt_name[DT_MAX_NAME];
    char cmdline[BOOTMOD_MAX_CMDLINE];
};

struct bootmodules {
    int nr_mods;
    struct bootmodule module[MAX_MODULES];
};

struct bootcmdlines {
    unsigned int nr_mods;
    struct bootcmdline cmdline[MAX_MODULES];
};

struct bootinfo {
    struct meminfo mem;
    /* The reserved regions are only used when booting using Device-Tree */
    struct meminfo reserved_mem;
    struct bootmodules modules;
    struct bootcmdlines cmdlines;
#ifdef CONFIG_ACPI
    struct meminfo acpi;
#endif
    bool static_heap;
};

extern struct bootinfo bootinfo;

struct bootmodule *add_boot_module(bootmodule_kind kind,
                                   paddr_t start, paddr_t size,
                                   bool domU);

struct bootcmdline *boot_cmdline_find_by_kind(bootmodule_kind kind);

struct bootcmdline *boot_cmdline_find_by_name(const char *name);

struct bootmodule *boot_module_find_by_kind(bootmodule_kind kind);

struct bootmodule *boot_module_find_by_addr_and_kind(bootmodule_kind kind,
                                                     paddr_t start);

const char * boot_module_kind_as_string(bootmodule_kind kind);

void add_boot_cmdline(const char *name, const char *cmdline,
                             bootmodule_kind kind, paddr_t start, bool domU);

#endif /* __XEN_SETUP_H__ */
