#ifndef __ASM_GRANT_TABLE_H__
#define __ASM_GRANT_TABLE_H__

/*
 * The region used by Xen on the memory will never be mapped in DOM0
 * memory layout. Therefore it can be used for the grant table.
 *
 * Only use the text section as it's always present and will contain
 * enough space for a large grant table
 */
#define gnttab_dom0_frames()                                             \
    min_t(unsigned int, opt_max_grant_frames, PFN_DOWN(_etext - _stext))

#endif /* __ASM_GRANT_TABLE_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
