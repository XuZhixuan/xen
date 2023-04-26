/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bootfdt.h>
#include <xen/bug.h>
#include <xen/compile.h>
#include <xen/console.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/percpu.h>
#include <xen/setup.h>
#include <xen/smp.h>
#include <xen/tasklet.h>
#include <xen/time.h>
#include <xen/virtual_region.h>
#include <xen/vmap.h>
#include <public/version.h>

#include <asm/early_printk.h>
#include <asm/processor.h>
#include <asm/plic.h>
#include <asm/traps.h>
#include <asm/uart.h>

/* Xen stack for bringing up the first CPU. */
unsigned char __initdata cpu0_boot_stack[STACK_SIZE]
    __aligned(STACK_SIZE);

domid_t max_init_domid = 0;
struct bootinfo __initdata bootinfo;

unsigned long total_pages;

static void test_run_in_exception(struct cpu_user_regs *regs)
{
    early_printk("If you see this message, ");
    early_printk("run_in_exception_handler is most likely working\n");
}

static void test_macros_from_bug_h(void)
{
    run_in_exception_handler(test_run_in_exception);
    WARN();
    early_printk("If you see this message, ");
    early_printk("WARN is most likely working\n");
}

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    assert_failed("need to be implemented");
}

void __init fdt_map(paddr_t dtb_addr)
{
    device_tree_flattened = early_fdt_map(dtb_addr);
    if ( !device_tree_flattened )
    {
        early_printk("wrong FDT\n");
        die();
    }
}

void __init noreturn start_xen(unsigned long bootcpu_id,
                               paddr_t dtb_addr)
{
    struct bootmodule *xen_bootmodule;
    size_t fdt_size;
    const char *cmdline;

    /*
     * tp register contains an address of physical cpu information.
     * So write physical CPU info of boot cpu to tp register
     * It will be used later by get_processor_id() to get process_id ( look at
     * <asm/processor.h> ):
     *   #define get_processor_id()    (tp->processor_id)
     */
    asm volatile ("mv tp, %0" : : "r"((unsigned long)&pcpu_info[bootcpu_id]));

    set_processor_id(bootcpu_id);

    remove_identity_mapping();

    percpu_init_areas();

    setup_virtual_regions(NULL, NULL);
    smp_clear_cpu_maps();

    early_printk("Hello from C env\n");

    trap_init();

    test_macros_from_bug_h();

    fdt_size = boot_fdt_info(device_tree_flattened, dtb_addr);

    cmdline = boot_fdt_cmdline(device_tree_flattened);
    printk("Command line: %s\n", cmdline);
    cmdline_parse(cmdline);

    /* Register Xen's load address as a boot module. */
    xen_bootmodule = add_boot_module(BOOTMOD_XEN,
                        (paddr_t)((unsigned long)_start + phys_offset),
                        (paddr_t)(_end - _start), false);

    BUG_ON(!xen_bootmodule);

    setup_mm();

    end_boot_allocator();

    /*
     * The memory subsystem has been initialized, we can now switch from
     * early_boot -> boot.
     */
    system_state = SYS_STATE_boot;

    vm_init();

    dt_unflatten_host_device_tree();

    tasklet_subsys_init();

    preinit_xen_time();

    plic_preinit();

    uart_init();
    console_init_preirq();
    console_init_ring();

    early_printk("All set up\n");

    for ( ;; )
        asm volatile ("wfi");

    unreachable();
}
