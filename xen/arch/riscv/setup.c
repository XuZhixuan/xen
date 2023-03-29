/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/compile.h>
#include <xen/init.h>
#include <xen/mm.h>

#include <asm/early_printk.h>
#include <asm/traps.h>

/* Xen stack for bringing up the first CPU. */
unsigned char __initdata cpu0_boot_stack[STACK_SIZE]
    __aligned(STACK_SIZE);

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

void __init noreturn start_xen(unsigned long bootcpu_id,
                               paddr_t dtb_addr)
{
    remove_identity_mapping();

    early_printk("Hello from C env\n");

    trap_init();

    test_macros_from_bug_h();

    early_printk("All set up\n");

    for ( ;; )
        asm volatile ("wfi");

    unreachable();
}
