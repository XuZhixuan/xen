#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/riscv_encoding.h>

/*
 * after relocate_enable_mmu macros t1 will contain phys offset which can be
 * to update sp and tp register, etc.
 */
.macro relocate_enable_mmu label
                jal     enable_mmu

                la      t1, phys_offset
                REG_L   t1, (t1)

                /* Calculate proper VA after jump from 1:1 mapping */
                la      t0, \label
                sub     t0, t0, t1

                /* Jump from 1:1 mapping world */
                jr      t0

        \label:
.endm

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

        la      t0, cpu0_boot_stack
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

        relocate_enable_mmu .L_primary_switched

        /*
         * cpu0_boot_stack address is 1:1 mapping related so it should be
         * recalculated after jump from 1:1 mapping world as 1:1 mapping
         * will be removed soon in start_xen().
         */
        la      t0, cpu0_boot_stack
        jal     reset_stack

        /* restore bootcpu_id and dtb address */
        mv      a0, s0
        mv      a1, s1

        tail    start_xen

        .section .text, "ax", %progbits

ENTRY(reset_stack)
        mv      sp, t0
        li      t0, STACK_SIZE - CPU_INFO_SIZE
        add     sp, sp, t0

        ret

        /*
         * a0 -> started hart id
         * a1 -> private data passed by boot cpu
         */
ENTRY(secondary_start_sbi)
        /* Mask all interrupts */
        csrw    CSR_SIE, zero

        /*
         * Disable FPU to detect illegal usage of
         * floating point in kernel space
         */
        li      t0, SSTATUS_FS
        csrc    CSR_SSTATUS, t0

        mv      t0, a1
        jal     reset_stack

        /*
         * Save hart id and private data passed by boot cpu as they can be
         * updated by C functions called between relocate_enable_mmu() and
         * smp_callin
         */
        mv      s0, a0
        mv      s1, a1

        relocate_enable_mmu .L_secondary_switched

        /*
         * t1 contains phys offset after relocate_enable_mmu macros.
         *
         * After jumping from 1:1 mapping sp may contain incorrect value ( in
         * case of linker address != load address ) so it should be updated
         * taking into account phys offset.
         */
        sub     t0, s1, t1
        jal     reset_stack

        /* restore hart id and private data passed by boot cpu */
        mv      a0, s0
        mv      a1, s1

        tail    smp_callin

        j       secondary_start_sbi
