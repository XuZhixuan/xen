#include <xen/bug.h>
#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/sched.h>

#include <asm/csr.h>
#include <asm/guest_access.h>
#include <asm/system.h>
#include <asm/traps.h>

unsigned long raw_copy_to_guest(void *to, const void *from, unsigned len)
{
    WARN();
    return -ENOSYS;
}

unsigned long raw_copy_from_guest(void *to, const void __user *from, unsigned len)
{
    WARN();
    return -ENOSYS;
}

unsigned long copy_to_guest_phys(struct domain *d,
                                 paddr_t gpa,
                                 void *buf,
                                 unsigned int len)
{
    /* XXX needs to handle faults */
    uint64_t addr = gpa;
    unsigned offset = addr & ~PAGE_MASK;

    /* This function may not yet be designed for non-dom0 domains */
    BUG_ON( d->domain_id != 0 );
    BUILD_BUG_ON((sizeof(addr)) < sizeof(vaddr_t));
    BUILD_BUG_ON((sizeof(addr)) < sizeof(paddr_t));

    printk(XENLOG_INFO "copying d%d 0x%02lx-0x%02lx to 0x%02lx-0x%02lx\n",
            d->domain_id, (unsigned long)buf, (unsigned long)buf+len, addr, addr+len);

    while ( len )
    {
        void *p;
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);
        struct page_info *page;

        page = p2m_get_page_from_gfn(d, gaddr_to_gfn(addr), NULL);
        if ( page == NULL )
            return len;

        p = __map_domain_page(page);
        p += offset;
        memcpy(p, buf, size);
        unmap_domain_page(p - offset);

        /* TODO: use put_page for reference counting here */

        len -= size;
        buf += size;
        addr += size;
        /*
         * After the first iteration, guest virtual address is correctly
         * aligned to PAGE_SIZE.
         */
        offset = 0;
    }

    return 0;
}

__attribute__((interrupt("supervisor")))
static void riscv_unpriv_trap(void)
{
    /* The trap details will be saved at address pointed by 'A0' register */
    register struct riscv_trap *trap asm("a0");

    /*
     * We assume that faulting unpriv load/store instruction is 4-byte long
     * and blindly increment SEPC by 4.
     */
    trap->sepc = csr_read(CSR_SEPC) + 4;
    csr_write(CSR_SEPC, trap->sepc);

    trap->scause = csr_read(CSR_SCAUSE);
    trap->stval = csr_read(CSR_STVAL);
    trap->htval = csr_read(CSR_HTVAL);
    trap->htinst = csr_read(CSR_HTINST);
}

/**
 * riscv_vcpu_unpriv_read -- Read machine word from Guest memory
 *
 * @vcpu: The VCPU pointer
 * @read_insn: Flag representing whether we are reading instruction
 * @guest_addr: Guest address to read
 * @trap: Output pointer to trap details
 */
unsigned long riscv_vcpu_unpriv_read(struct vcpu *vcpu,
                     bool read_insn,
                     unsigned long guest_addr,
                     struct riscv_trap *trap)
{
    register unsigned long taddr asm("a0") = (unsigned long)trap;
    register unsigned long ttmp asm("a1");
    register unsigned long val asm("t0");
    register unsigned long tmp asm("t1");
    register unsigned long addr asm("t2") = guest_addr;
    unsigned long flags;
    unsigned long old_stvec, old_hstatus;

    local_irq_save(flags);

    old_hstatus = csr_swap(CSR_HSTATUS, vcpu->arch.hstatus);
    old_stvec = csr_swap(CSR_STVEC, (unsigned long)&riscv_unpriv_trap);

    if (read_insn) {
        /*
         * HLVX.HU instruction
         * 0110010 00011 rs1 100 rd 1110011
         */
        asm volatile ("\n"
            ".option push\n"
            ".option norvc\n"
            "add %[ttmp], %[taddr], 0\n"
            /*
             * HLVX.HU %[val], (%[addr])
             * HLVX.HU t0, (t2)
             * 0110010 00011 00111 100 00101 1110011
             */
            ".word 0x6433c2f3\n"
            "andi %[tmp], %[val], 3\n"
            "addi %[tmp], %[tmp], -3\n"
            "bne %[tmp], zero, 2f\n"
            "addi %[addr], %[addr], 2\n"
            /*
             * HLVX.HU %[tmp], (%[addr])
             * HLVX.HU t1, (t2)
             * 0110010 00011 00111 100 00110 1110011
             */
            ".word 0x6433c373\n"
            "sll %[tmp], %[tmp], 16\n"
            "add %[val], %[val], %[tmp]\n"
            "2:\n"
            ".option pop"
        : [val] "=&r" (val), [tmp] "=&r" (tmp),
          [taddr] "+&r" (taddr), [ttmp] "+&r" (ttmp),
          [addr] "+&r" (addr) : : "memory");

        if (trap->scause == CAUSE_LOAD_PAGE_FAULT)
            trap->scause = CAUSE_FETCH_PAGE_FAULT;
    } else {
        /*
         * HLV.D instruction
         * 0110110 00000 rs1 100 rd 1110011
         *
         * HLV.W instruction
         * 0110100 00000 rs1 100 rd 1110011
         */
        asm volatile ("\n"
            ".option push\n"
            ".option norvc\n"
            "add %[ttmp], %[taddr], 0\n"
#ifdef CONFIG_64BIT
            /*
             * HLV.D %[val], (%[addr])
             * HLV.D t0, (t2)
             * 0110110 00000 00111 100 00101 1110011
             */
            ".word 0x6c03c2f3\n"
#else
            /*
             * HLV.W %[val], (%[addr])
             * HLV.W t0, (t2)
             * 0110100 00000 00111 100 00101 1110011
             */
            ".word 0x6803c2f3\n"
#endif
            ".option pop"
        : [val] "=&r" (val),
          [taddr] "+&r" (taddr), [ttmp] "+&r" (ttmp)
        : [addr] "r" (addr) : "memory");
    }

    csr_write(CSR_HSTATUS, old_hstatus);
    csr_write(CSR_STVEC, old_stvec);

    local_irq_restore(flags);

    return val;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
