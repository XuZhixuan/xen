/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bootfdt.h>
#include <xen/bug.h>
#include <xen/compile.h>
#include <xen/console.h>
#include <xen/cpu.h>
#include <xen/device_tree.h>
#include <xen/domain.h>
#include <xen/init.h>
#include <xen/keyhandler.h>
#include <xen/mm.h>
#include <xen/percpu.h>
#include <xen/rcupdate.h>
#include <xen/sched.h>
#include <xen/serial.h>
#include <xen/setup.h>
#include <xen/smp.h>
#include <xen/tasklet.h>
#include <xen/time.h>
#include <xen/timer.h>
#include <xen/virtual_region.h>
#include <xen/vmap.h>
#include <public/version.h>

#include <asm/current.h>
#include <asm/early_printk.h>
#include <asm/processor.h>
#include <asm/plic.h>
#include <asm/sbi.h>
#include <asm/system.h>
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

static __used void init_done(void)
{
    /* TODO: free init memory */
    startup_cpu_idle_loop();
}

static bool __init is_dom0less_mode(void)
{
    struct bootmodules *mods = &bootinfo.modules;
    struct bootmodule *mod;
    unsigned int i;
    bool dom0found = false;
    bool domUfound = false;

    /* Look into the bootmodules */
    for ( i = 0 ; i < mods->nr_mods ; i++ )
    {
        mod = &mods->module[i];
        /* Find if dom0 and domU kernels are present */
        if ( mod->kind == BOOTMOD_KERNEL )
        {
            if ( mod->domU == false )
            {
                dom0found = true;
                break;
            }
            else
                domUfound = true;
        }
    }

    /*
     * If there is no dom0 kernel but at least one domU, then we are in
     * dom0less mode
     */
    return ( !dom0found && domUfound );
}

void __init noreturn start_xen(unsigned long bootcpu_id,
                               paddr_t dtb_addr)
{
    struct bootmodule *xen_bootmodule;
    size_t fdt_size;
    const char *cmdline;
    struct domain *d;
    unsigned int i;

    /*
     * tp register contains an address of physical cpu information.
     * So write physical CPU info of boot cpu to tp register
     * It will be used later by get_processor_id() to get process_id ( look at
     * <asm/processor.h> ):
     *   #define get_processor_id()    (tp->processor_id)
     */
    asm volatile ("mv tp, %0" : : "r"((unsigned long)&pcpu_info[0]));

    set_processor_id(0);

    percpu_init_areas();

    smp_setup_processor_id(bootcpu_id);

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

    if ( sbi_probe_extension(SBI_EXT_HSM) < 0 )
        panic("HSM extenstion isn't supported\n");

    smp_init_cpus();
    nr_cpu_ids = smp_get_max_cpus();
    printk(XENLOG_INFO "SMP: Allowing %u CPUs\n", nr_cpu_ids);

    do_presmp_initcalls();

    preinit_xen_time();

    plic_preinit();

    uart_init();
    console_init_preirq();
    console_init_ring();

    init_xen_time();

    init_timer_interrupt();

    timer_init();

    rcu_init();

    setup_system_domains();

    local_irq_enable();

   /* Init idle domain */
    scheduler_init();
    set_current(idle_vcpu[0]);

    console_init_postirq();

    smp_prepare_cpus();

    for_each_present_cpu ( i )
    {
        if ( (num_online_cpus() < nr_cpu_ids) && !cpu_online(i) )
        {
            int ret = cpu_up(i);
            if ( ret != 0 )
                printk("Failed to bring up CPU %u (error %d)\n", i, ret);
        }
    }

    /*
     * identity mapping should be removed after bring up CPUs as there is
     * a part of code in head.S ( secondary_start_sbi() ) which requires to
     * have 1:1 mapping ( to switch from 1:1 mapping world, look at
     * relocate_enable_mmu() in head.S ).
     */
    remove_identity_mapping();

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());

    do_initcalls();

    /* Create initial domain 0. */
    if ( !is_dom0less_mode() )
        create_dom0();
    else
        printk(XENLOG_INFO "Xen dom0less mode detected\n");

    create_domUs();

    console_endboot();

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    early_printk("All set up\n");

    system_state = SYS_STATE_active;

    for_each_domain( d )
        domain_unpause_by_systemcontroller(d);

    /* Switch on to the dynamically allocated stack for the idle vcpu
     * since the static one we're running on is about to be freed. */
    memcpy(idle_vcpu[0]->arch.cpu_info, get_cpu_info(),
           sizeof(struct cpu_info));
    switch_stack_and_jump(idle_vcpu[0]->arch.cpu_info, init_done);

    for ( ;; )
        asm volatile ("wfi");

    unreachable();
}
