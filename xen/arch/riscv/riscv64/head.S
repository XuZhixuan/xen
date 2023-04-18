#include <asm/asm.h>
#include <asm/riscv_encoding.h>

        .section .text.header, "ax", %progbits

        /*
         * OpenSBI pass to start():
         *   a0 -> hart_id ( bootcpu_id )
         *   a1 -> dtb_base 
         */
ENTRY(start)
        /* Mask all interrupts */
        csrw    CSR_SIE, zero

        /*
         * Disable FPU to detect illegal usage of
         * floating point in kernel space
         */
        li      t0, SSTATUS_FS
        csrc    CSR_SSTATUS, t0

        /* Clear the BSS */
        la      t3, __bss_start
        la      t4, __bss_end
.L_clear_bss:
        REG_S   zero, (t3)
        add     t3, t3, __SIZEOF_POINTER__
        bltu    t3, t4, .L_clear_bss

        jal     reset_stack

        /*
         * save hart_id and dtb_base as a0 and a1 register can be used
         * by C code ( f.e. setup_initial_pagetables will update a0 and
         * a1 )
         */
        mv      s0, a0
        mv      s1, a1

        jal     calc_phys_offset

        jal     setup_initial_pagetables

        mv      a0, s1
        jal     fdt_map

        jal     setup_fixmap_mappings

        jal     enable_mmu

        la      t1, phys_offset
        REG_L   t1, (t1)

        /* Calculate proper VA after jump from 1:1 mapping */
        la      t0, .L_primary_switched
        sub     t0, t0, t1

        /* Jump from 1:1 mapping world */
        jr      t0

.L_primary_switched:
        /*
         * cpu0_boot_stack address is 1:1 mapping related so it should be
         * recalculated after jump from 1:1 mapping world as 1:1 mapping
         * will be removed soon in start_xen().
         */
        jal     reset_stack

        /* restore bootcpu_id and dtb address */
        mv      a0, s0
        mv      a1, s1

        tail    start_xen

        .section .text, "ax", %progbits

ENTRY(reset_stack)
        la      sp, cpu0_boot_stack
        li      t0, STACK_SIZE
        add     sp, sp, t0

        ret

