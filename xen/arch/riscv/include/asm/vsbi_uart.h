/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __ASM_RISCV_VSBI_UART_H__
#define __ASM_RISCV_VSBI_UART_H__

#include <public/domctl.h>
#include <public/io/ring.h>
#include <public/io/console.h>
#include <xen/mm.h>

/* helper macros */
#define VSBI_UART_LOCK(d,flags) spin_lock_irqsave(&(d)->arch.vsbi_uart.lock, flags)
#define VSBI_UART_UNLOCK(d,flags) spin_unlock_irqrestore(&(d)->arch.vsbi_uart.lock, flags)

#define VSBI_UART_FIFO_SIZE 32
/* Same size as vsbi_uart_BUF_SIZE, used in vsbi_uart.c */
#define VSBI_UART_OUT_BUF_SIZE 128
struct vsbi_uart_xen_backend {
    char in[VSBI_UART_FIFO_SIZE];
    char out[VSBI_UART_OUT_BUF_SIZE];
    XENCONS_RING_IDX in_cons, in_prod;
    XENCONS_RING_IDX out_prod;
};

struct vsbi_uart {
    bool backend_in_domain;
    union {
        struct {
            void *ring_buf;
            struct page_info *ring_page;
        } dom;
        struct vsbi_uart_xen_backend *xen;
    } backend;

    spinlock_t  lock;
};

struct vsbi_uart_init_info {
};

int domain_vsbi_uart_init(struct domain *d , struct vsbi_uart_init_info *info);
void domain_vsbi_uart_deinit(struct domain *d);

void vsbi_uart_putchar(struct cpu_user_regs *regs);
void vsbi_uart_getchar(struct cpu_user_regs *regs);

void vsbi_uart_rx_char_xen(struct domain *d, char c);

unsigned long get_cons_ring_char(void);

#endif /* __ASM_RISCV_VSBI_UART_H__ */
