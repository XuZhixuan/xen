/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/compile.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/setup.h>
#include <public/version.h>

#include <asm/early_printk.h>
#include <asm/processor.h>
#include <asm/traps.h>

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

void __init noreturn start_xen(unsigned long bootcpu_id,
                               paddr_t dtb_addr)
{
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

    early_printk("Hello from C env\n");

    trap_init();

    test_macros_from_bug_h();

    early_printk("All set up\n");

    for ( ;; )
        asm volatile ("wfi");

    unreachable();
}
