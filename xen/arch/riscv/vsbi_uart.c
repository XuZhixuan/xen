#define XEN_WANT_FLEX_CONSOLE_RING 1

#include <xen/console.h>
#include <xen/sched.h>

#include <asm/sbi.h>
#include <asm/vsbi_uart.h>

int domain_vsbi_uart_init(struct domain *d , struct vsbi_uart_init_info *info)
{
    int rc = 0;
    struct vsbi_uart *vsbi_uart = &d->arch.vsbi_uart;

    if ( vsbi_uart->backend.dom.ring_buf )
    {
        printk("%s: ring_buf != 0\n", __func__);
        return -EINVAL;
    }

/*
    if ( is_domain_direct_mapped(d) )
        printk("domain is direct mapped\n");
    else
        printk("domain isn't direct mapped\n");
*/

    /*
     * info is NULL when the backend is in Xen.
     * info is != NULL when the backend is in a domain.
     */
    if ( info != NULL )
    {
        printk("%s: vsbi_uart backend in a domain isn't supported\n", __func__);
        rc = -EOPNOTSUPP;
        goto out;
    }
    else
    {
        vsbi_uart->backend_in_domain = false;

        vsbi_uart->backend.xen = xzalloc(struct vsbi_uart_xen_backend);
        if ( vsbi_uart->backend.xen == NULL )
        {
            rc = -ENOMEM;
            goto out;
        }
    }

    spin_lock_init(&vsbi_uart->lock);

    return 0;

out:
    domain_vsbi_uart_deinit(d);

    return rc;
}

void domain_vsbi_uart_deinit(struct domain *d)
{
    struct vsbi_uart *vsbi_uart = &d->arch.vsbi_uart;

    if ( vsbi_uart->backend_in_domain )
        printk("%s: backed in a domain isn't supported\n", __func__);
    else
        XFREE(vsbi_uart->backend.xen);
}

void vsbi_uart_putchar(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;

    struct vsbi_uart *vsbi_uart = &d->arch.vsbi_uart;
    struct vsbi_uart_xen_backend *intf = vsbi_uart->backend.xen;
    struct domain *input = console_input_domain();

    uint8_t data = regs->a0;

    unsigned long flags;

    if ( !intf )
    {
        sbi_console_putchar(data);
        return;
    }

    VSBI_UART_LOCK(d, flags);

    intf->out[intf->out_prod++] = data;
    if ( d == input )
    {
        if ( intf->out_prod == 1 )
        {
            printk("%c", data);
            intf->out_prod = 0;
        }
        else
        {
            if ( data != '\n' )
                intf->out[intf->out_prod++] = '\n';
            intf->out[intf->out_prod++] = '\0';
            printk("%s", intf->out);
            intf->out_prod = 0;
        }
    }
    else
    {
        if ( intf->out_prod == VSBI_UART_OUT_BUF_SIZE - 2 ||
             data == '\n' )
        {
            if ( data != '\n' )
                intf->out[intf->out_prod++] = '\n';
            intf->out[intf->out_prod++] = '\0';
            printk("DOM%u: %s", d->domain_id, intf->out);
            intf->out_prod = 0;
        }
    } 

    VSBI_UART_UNLOCK(d, flags);
    if ( input != NULL )
        rcu_unlock_domain(input);
}

void vsbi_uart_getchar(struct cpu_user_regs *regs)
{
    unsigned long flags;
    unsigned long data = -1UL;
    struct vcpu *v = current;
    struct domain *d = v->domain;
    struct vsbi_uart *vsbi_uart = &d->arch.vsbi_uart;
    struct vsbi_uart_xen_backend *intf = vsbi_uart->backend.xen;
    XENCONS_RING_IDX in_cons, in_prod;


    if ( !intf )
    {
        regs->a0 = (unsigned long)get_cons_ring_char();
        return;
    }

    VSBI_UART_LOCK(d, flags);

    in_cons = intf->in_cons;
    in_prod = intf->in_prod;

    smp_rmb();

    if ( xencons_queued(in_prod, in_cons, sizeof(intf->in)) > 0 )
    {
        data = intf->in[xencons_mask(in_cons, sizeof(intf->in))];
        in_cons += 1;
        smp_mb();
        intf->in_cons = in_cons;
    }

    regs->a0 = data;

    VSBI_UART_UNLOCK(d, flags);
}

/*
 * vsbi_uart_rx_char_xen adds a char to a domain's vsbi uart receive buffer.
 * It is only used when the vsbi uart backend is in Xen.
 */
void vsbi_uart_rx_char_xen(struct domain *d, char c)
{
    unsigned long flags;
    struct vsbi_uart *vsbi_uart = &d->arch.vsbi_uart;
    struct vsbi_uart_xen_backend *intf = vsbi_uart->backend.xen;
    XENCONS_RING_IDX in_cons, in_prod;

    ASSERT(!vsbi_uart->backend_in_domain);
    VSBI_UART_LOCK(d, flags);

    in_cons = intf->in_cons;
    in_prod = intf->in_prod;
    if ( xencons_queued(in_prod, in_cons, sizeof(intf->in)) == sizeof(intf->in) )
    {
        VSBI_UART_UNLOCK(d, flags);
        return;
    }

    intf->in[xencons_mask(in_prod, sizeof(intf->in))] = c;
    intf->in_prod = ++in_prod;

    VSBI_UART_UNLOCK(d, flags);
}
