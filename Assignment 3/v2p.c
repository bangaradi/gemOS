#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

#define MAX_LENGTH (2 * 1024 * 1024)

#define PAGE_SIZE 4096

#define MASK 511
#define PTE_PFN_MASK 0xFFFFFFFFFF000

#define PTE_P 0x001
#define PTE_W 0x002
#define PTE_U 0x004

#define PTE_PRESENT 0x1

#define PTE_RW_BIT (1 << 3)

void tlb_flush() {
    u64 cr3;
    asm volatile(
        "mov %%cr3, %0;"
        : "=r"(cr3)
        :
        : "memory");

    asm volatile(
        "mov %0, %%cr3;"
        :
        : "r"(cr3)
        : "memory");
}

u64 *get_pte_entry(u64 cr3, u64 vaddr) {
    u64 *pgd_base = (u64 *)osmap(cr3);
    u64 pgd_index = (vaddr >> 39) & MASK;
    u64 pud_index = (vaddr >> 30) & MASK;
    u64 pmd_index = (vaddr >> 21) & MASK;
    u64 pte_index = (vaddr >> 12) & MASK;

    u64 *pud, *pmd, *pte;
    if (!(pgd_base[pgd_index] & PTE_P)) {
        return NULL;
    }
    pud = (u64 *)osmap(pgd_base[pgd_index] >> 12);

    if (!(pud[pud_index] & PTE_P)) {
        return NULL;
    }

    pmd = (u64 *)osmap(pud[pud_index] >> 12);

    if (!(pmd[pmd_index] & PTE_P)) {
        return NULL;
    }

    pte = (u64 *)osmap(pmd[pmd_index] >> 12);

    if (!(pte[pte_index] & PTE_P)) {
        return NULL;
    }

    return &pte[pte_index];
}

void put_page_here(u32 pgd, u32 pgd_parent, u64 start){
    u64* pgd_base = (u64*)osmap(pgd);
    u64* pgd_base_parent = (u64*)osmap(pgd_parent);
    u64 pgd_index = (start >> 39) & MASK;
    u64 pud_index = (start >> 30) & MASK;
    u64 pmd_index = (start >> 21) & MASK;
    u64 pte_index = (start >> 12) & MASK;
    u64 pgd_index_parent = (start >> 39) & MASK;
    u64 pud_index_parent = (start >> 30) & MASK;
    u64 pmd_index_parent = (start >> 21) & MASK;
    u64 pte_index_parent = (start >> 12) & MASK;

    u64 *pud, *pmd, *pte;
    u64 *pud_parent, *pmd_parent, *pte_parent;

    if (!(pgd_base[pgd_index] & PTE_P)) {
        u32 pud_pfn = os_pfn_alloc(OS_PT_REG);
        pgd_base[pgd_index] = (pud_pfn << 12) | 0x19;
    }
    pud = (u64 *)osmap((u32)(pgd_base[pgd_index] >> 12));

    if (!(pud[pud_index] & PTE_P)) {
        u32 pmd_pfn = os_pfn_alloc(OS_PT_REG);
        pud[pud_index] = (pmd_pfn << 12) | 0x19;
    }
    pmd = (u64 *)osmap((u32)(pud[pud_index] >> 12));

    if (!(pmd[pmd_index] & PTE_P)) {
        u32 pte_pfn = os_pfn_alloc(OS_PT_REG);
        pmd[pmd_index] = (pte_pfn << 12) | 0x19;
    }
    pte = (u64 *)osmap((u32)(pmd[pmd_index] >> 12));

    pte[pte_index] = 0x0;

    if (!(pgd_base_parent[pgd_index_parent] & PTE_P)) {
        return;
    }
    pud_parent = (u64 *)osmap((u32)(pgd_base_parent[pgd_index_parent] >> 12));

    if (!(pud_parent[pud_index_parent] & PTE_P)) {
        return;
    }
    pmd_parent = (u64 *)osmap((u32)(pud_parent[pud_index_parent] >> 12));

    if (!(pmd_parent[pmd_index_parent] & PTE_P)) {
        return;
    }
    pte_parent = (u64 *)osmap((u32)(pmd_parent[pmd_index_parent] >> 12));
    
    if (!(pte_parent[pte_index_parent] & PTE_P)) {
        return;
    }

    u32 page_pfn_number = pte_parent[pte_index_parent] >> 12;
    get_pfn(page_pfn_number);
    pte[pte_index] = pte_parent[pte_index_parent];
    pte[pte_index] = pte[pte_index] & ~(0x8);
    pte_parent[pte_index_parent] = pte_parent[pte_index_parent] & ~(0x8);
}




long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot) {    
    if (addr < MMAP_AREA_START || addr >= MMAP_AREA_END || length <= 0) {
        return -EINVAL;
    }

    if (prot & PROT_EXEC) {
        return -EINVAL;
    }

    if (!(prot == PROT_READ || prot == (PROT_READ | PROT_WRITE))) {
        return -EINVAL;
    }

    if (length % PAGE_SIZE) {
        length = (length / PAGE_SIZE + 1) * PAGE_SIZE;
    }

    u64 mprotect_end = addr + length;
    struct vm_area *vma = current->vm_area;
    struct vm_area *prev_vma = NULL;

    int changed = 0;

    while (vma) {
        if (vma->vm_end <= addr || vma->vm_start >= mprotect_end) {
            prev_vma = vma;
            vma = vma->vm_next;
            continue;
        }

        if (addr <= vma->vm_start && mprotect_end >= vma->vm_end) {
            vma->access_flags = prot;
            changed = 1;
            u64 start_addr = (vma->vm_start > addr) ? vma->vm_start : addr;
            u64 end_addr = (vma->vm_end < mprotect_end) ? vma->vm_end : mprotect_end;

            for (u64 page_addr = start_addr; page_addr < end_addr; page_addr += PAGE_SIZE) {
                u64 *pte = get_pte_entry(current->pgd, page_addr);
                if (pte && (*pte & PTE_PRESENT)) {
                    if (prot == PROT_WRITE || prot == (PROT_READ | PROT_WRITE)) {
                        if(get_pfn_refcount((*pte & PTE_PFN_MASK) >> 12) == 1){
                            *pte |= PTE_RW_BIT;
                        }else{
                            continue;
                        }
                    } else {
                        *pte &= ~PTE_RW_BIT;
                    }
                }
            }
        } else if (addr > vma->vm_start && mprotect_end < vma->vm_end) {
            struct vm_area *new_vma1 = os_alloc(sizeof(struct vm_area));
            struct vm_area *new_vma2 = os_alloc(sizeof(struct vm_area));
            if (!new_vma1 || !new_vma2) {
                return -EINVAL;
            }

            *new_vma1 = *vma;
            *new_vma2 = *vma;
            new_vma1->vm_end = addr;
            new_vma2->vm_start = mprotect_end;
            vma->vm_start = addr;
            vma->vm_end = mprotect_end;
            vma->access_flags = prot;

            new_vma2->vm_next = vma->vm_next;
            vma->vm_next = new_vma2;
            new_vma1->vm_next = vma;
            if (prev_vma) {
                prev_vma->vm_next = new_vma1;
            } else {
                current->vm_area = new_vma1;
            }

            stats->num_vm_area += 2;
            u64 start_addr = (vma->vm_start > addr) ? vma->vm_start : addr;
            u64 end_addr = (vma->vm_end < mprotect_end) ? vma->vm_end : mprotect_end;

            for (u64 page_addr = start_addr; page_addr < end_addr; page_addr += PAGE_SIZE) {
                u64 *pte = get_pte_entry(current->pgd, page_addr);
                if (pte && (*pte & PTE_PRESENT)) {
                    if (prot == PROT_WRITE || prot == (PROT_READ | PROT_WRITE)) {
                        if(get_pfn_refcount((*pte & PTE_PFN_MASK) >> 12) == 1){
                            *pte |= PTE_RW_BIT;
                        }else{
                            continue;
                        }
                    } else {
                        *pte &= ~PTE_RW_BIT;
                    }
                }
            }
            changed = 1;
            break;
        } else {
            if (vma->vm_start < addr) {
                struct vm_area *new_vma = os_alloc(sizeof(struct vm_area));
                if (!new_vma) {
                    return -EINVAL;
                }
                *new_vma = *vma;
                new_vma->vm_start = addr;
                vma->vm_end = addr;
                new_vma->vm_next = vma->vm_next;
                vma->vm_next = new_vma;
                stats->num_vm_area++;
                vma = new_vma;
            }

            if (vma->vm_end > mprotect_end) {
                struct vm_area *new_vma = os_alloc(sizeof(struct vm_area));
                if (!new_vma) {
                    return -EINVAL;
                }
                *new_vma = *vma;
                new_vma->vm_end = vma->vm_end;
                new_vma->vm_start = mprotect_end;
                vma->vm_end = mprotect_end;
                new_vma->vm_next = vma->vm_next;
                vma->vm_next = new_vma;
                stats->num_vm_area++;
            }

            vma->access_flags = prot;
            changed = 1;

            u64 start_addr = (vma->vm_start > addr) ? vma->vm_start : addr;
            u64 end_addr = (vma->vm_end < mprotect_end) ? vma->vm_end : mprotect_end;

            for (u64 page_addr = start_addr; page_addr < end_addr; page_addr += PAGE_SIZE) {
                u64 *pte = get_pte_entry(current->pgd, page_addr);
                if (pte && (*pte & PTE_PRESENT)) {
                    if (prot == PROT_WRITE || prot == (PROT_READ | PROT_WRITE)) {
                        if(get_pfn_refcount((*pte & PTE_PFN_MASK) >> 12) == 1){
                            *pte |= PTE_RW_BIT;
                        }else{
                            continue;
                        }
                    } else {
                        *pte &= ~PTE_RW_BIT;
                    }
                }
            }
        }

        if (prev_vma && prev_vma->vm_end == vma->vm_start && prev_vma->access_flags == vma->access_flags) {
            prev_vma->vm_end = vma->vm_end;
            prev_vma->vm_next = vma->vm_next;
            os_free(vma, sizeof(struct vm_area));
            stats->num_vm_area--;
            vma = prev_vma->vm_next;
        } else {
        if (vma->vm_next && vma->vm_end == vma->vm_next->vm_start && vma->access_flags == vma->vm_next->access_flags) {
            struct vm_area *next_vma = vma->vm_next;
            vma->vm_end = next_vma->vm_end;
            vma->vm_next = next_vma->vm_next;
            os_free(next_vma, sizeof(struct vm_area));
            stats->num_vm_area--;
    }
        prev_vma = vma;
        vma = vma->vm_next;
}
    }

    tlb_flush();
    return changed ? 0 : -1;
}





long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags) {
    
    if (!current->vm_area) {
        current->vm_area = os_alloc(sizeof(struct vm_area));
        if (!current->vm_area) {
            return -EINVAL;
        }
        current->vm_area->vm_start = MMAP_AREA_START;
        current->vm_area->vm_end = MMAP_AREA_START + PAGE_SIZE;
        current->vm_area->access_flags = 0;
        current->vm_area->vm_next = NULL;
        stats->num_vm_area++;
    }

    if (length <= 0 || length > MAX_LENGTH) {
        return -EINVAL;
    }

    if (flags != 0 && flags != MAP_FIXED) {
        return -EINVAL;
    }

    if (prot & PROT_EXEC) {
        return -EINVAL;
    }

    if (!(prot == PROT_READ || prot == (PROT_READ | PROT_WRITE))) {
        return -EINVAL;
    }

    if (addr && (addr % PAGE_SIZE)) {
        return -EINVAL;
    }

    if (length % PAGE_SIZE) {
        length = (length / PAGE_SIZE + 1) * PAGE_SIZE;
    }

    if (stats->num_vm_area >= 128) {
        return -EINVAL;
    }

    if ((flags & MAP_FIXED) && addr == 0) {
        return -EINVAL;
    }

    struct vm_area *new_vma = os_alloc(sizeof(struct vm_area));
    if (!new_vma) {
        return -EINVAL;
    }
    stats->num_vm_area++;

    new_vma->access_flags = prot;
    new_vma->vm_next = NULL;

    u64 new_addr = addr;

    if (!addr || !(flags & MAP_FIXED)) {
        new_addr = MMAP_AREA_START;
        struct vm_area *vma = current->vm_area;

        if (addr && !(flags & MAP_FIXED)) {
            new_addr = addr;
        }

        while (vma) {
            if (new_addr < vma->vm_end) {
                new_addr = (vma->vm_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
            }
            if (vma->vm_next && new_addr >= vma->vm_next->vm_start) {
                vma = vma->vm_next;
            } else {
                break;
            }
        }

        if (new_addr + length > MMAP_AREA_END) {
            os_free(new_vma, sizeof(struct vm_area));
            stats->num_vm_area--;
            return -EINVAL;
        }
    } else {
        if (addr < MMAP_AREA_START || addr + length > MMAP_AREA_END) {
            os_free(new_vma, sizeof(struct vm_area));
            stats->num_vm_area--;
            return -EINVAL;
        }
    }

    new_vma->vm_start = new_addr;
    new_vma->vm_end = new_addr + length;

    if (flags & MAP_FIXED) {
        struct vm_area *vma = current->vm_area;
        while (vma->vm_next && vma->vm_next->vm_start < new_vma->vm_end) {
            if (vma->vm_next->vm_end > new_vma->vm_start) {
                os_free(new_vma, sizeof(struct vm_area));
                stats->num_vm_area--;
                return -EINVAL;
            }
            vma = vma->vm_next;
        }
    }

    struct vm_area *vma = current->vm_area;
    while (vma->vm_next && vma->vm_next->vm_start <= new_vma->vm_start) {
        vma = vma->vm_next;
    }

    if (vma->vm_end == new_vma->vm_start && vma->access_flags == new_vma->access_flags) {
        vma->vm_end = new_vma->vm_end;
        os_free(new_vma, sizeof(struct vm_area));
        stats->num_vm_area--;
    } else {
        new_vma->vm_next = vma->vm_next;
        vma->vm_next = new_vma;
    }

    if (new_vma->vm_next && new_vma->vm_end == new_vma->vm_next->vm_start && new_vma->access_flags == new_vma->vm_next->access_flags) {
        struct vm_area *next_vma = new_vma->vm_next;
        new_vma->vm_end = next_vma->vm_end;
        new_vma->vm_next = next_vma->vm_next;
        os_free(next_vma, sizeof(struct vm_area));
        stats->num_vm_area--;
    }

    return (long)new_vma->vm_start;
}





long vm_area_unmap(struct exec_context *current, u64 addr, int length) {
    if (addr < MMAP_AREA_START || addr >= MMAP_AREA_END || length <= 0) {
        return -EINVAL;
    }

    if (length % PAGE_SIZE) {
        length = (length / PAGE_SIZE + 1) * PAGE_SIZE;
    }

    u64 unmap_end = addr + length;
    struct vm_area *vma = current->vm_area;
    struct vm_area *prev_vma = NULL;
    int unmapped = 0;

    while (vma) {
        if (vma->vm_end > addr && vma->vm_start < unmap_end) {
            if (vma->vm_start >= addr && vma->vm_end <= unmap_end) {
                struct vm_area *temp = vma;
                if (prev_vma) {
                    prev_vma->vm_next = vma->vm_next;
                } else {
                    current->vm_area = vma->vm_next;
                }
                vma = vma->vm_next;
                os_free(temp, sizeof(struct vm_area));
                stats->num_vm_area--;
            } else if (vma->vm_start < addr && vma->vm_end > unmap_end) {
                struct vm_area *new_vma = os_alloc(sizeof(struct vm_area));
                if (!new_vma) {
                    return -EINVAL;
                }
                *new_vma = *vma;
                new_vma->vm_start = unmap_end;
                vma->vm_end = addr;
                new_vma->vm_next = vma->vm_next;
                vma->vm_next = new_vma;
                stats->num_vm_area++;
                vma = new_vma->vm_next;
            } else {
                if (vma->vm_start < addr) {
                    vma->vm_end = addr;
                } else {
                    vma->vm_start = unmap_end;
                }
            }

            for (u64 page_addr = addr; page_addr < unmap_end; page_addr += PAGE_SIZE) {
                u64 *pte = get_pte_entry(current->pgd, page_addr);
                if (pte && (*pte & PTE_PRESENT)) {
                    u64 pfn = (*pte & PTE_PFN_MASK) >> 12;
                    if(get_pfn_refcount(pfn) == 1){
                        put_pfn((u32) pfn);
                        os_pfn_free(USER_REG, pfn);
                        *pte &= 0x0;
                        continue;
                    }else{
                        put_pfn((u32) pfn);
                    }
                }
            }

            unmapped = 1;
        } else {
            prev_vma = vma;
        }
        vma = vma->vm_next;
    }
    tlb_flush();
    return unmapped ? 0 : 0;
}










/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code) {

    if (addr < MMAP_AREA_START || addr >= MMAP_AREA_END) {
        return -1;
    }

    struct vm_area *vma = current->vm_area;
    while (vma) {
        if (addr >= vma->vm_start && addr < vma->vm_end) {
            int is_write_fault = (error_code == 0x6 || error_code == 0x7);
            int has_write_permission = (vma->access_flags & PROT_WRITE);

            if (is_write_fault && !has_write_permission) {
                return -1;
            }
            u64 *pgd_base = (u64 *)osmap(current->pgd);
            u64 pgd_index = (addr >> 39) & MASK;
            u64 pud_index = (addr >> 30) & MASK;
            u64 pmd_index = (addr >> 21) & MASK;
            u64 pte_index = (addr >> 12) & MASK;

            u64 *pud, *pmd, *pte;
            if (!(pgd_base[pgd_index] & PTE_P)) {
                u32 pud_pfn = os_pfn_alloc(OS_PT_REG);
                pgd_base[pgd_index] = (pud_pfn << 12) | 0x19;
            }
            pud = (u64 *)osmap(pgd_base[pgd_index] >> 12);

            if (!(pud[pud_index] & PTE_P)) {
                u32 pmd_pfn = os_pfn_alloc(OS_PT_REG);
                pud[pud_index] = (pmd_pfn << 12) | 0x19;
            }
            pmd = (u64 *)osmap(pud[pud_index] >> 12);

            if (!(pmd[pmd_index] & PTE_P)) {
                u32 pte_pfn = os_pfn_alloc(OS_PT_REG);
                pmd[pmd_index] = (pte_pfn << 12) | 0x19;
            }
            pte = (u64 *)osmap(pmd[pmd_index] >> 12);
            if (!(pte[pte_index] & PTE_P)) {
                u32 page_frame_pfn = os_pfn_alloc(USER_REG);
                if (vma->access_flags != (PROT_READ|PROT_WRITE)) {
                    pte[pte_index] = (page_frame_pfn << 12) | 0x11;
                } else {
                    pte[pte_index] = (page_frame_pfn << 12) | 0x19;
                }
            }

            if (error_code == 0x7) {
                handle_cow_fault(current, addr, vma->access_flags);
            }

            return 1;
        }
        vma = vma->vm_next;
    }

    return -1;
}





/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the 
 * end of this function (e.g., setup_child_context etc.)
 */






long do_cfork(){
        u32 pid;
        struct exec_context *new_ctx = get_new_ctx();
        struct exec_context *ctx = get_current_ctx();
        /* Do not modify above lines
        * 
        * */   
        /*--------------------- Your code [start]---------------*/
        pid = new_ctx->pid;
        memcpy(new_ctx, ctx, sizeof(struct exec_context));
        new_ctx->pid = pid;
        new_ctx->ppid = ctx->pid;

        u32 new_pgd = os_pfn_alloc(OS_PT_REG);
        new_ctx->pgd = new_pgd;

        for (int i = 0; i < MAX_OPEN_FILES; i++) {
            if (ctx->files[i]) {
                new_ctx->files[i] = ctx->files[i];
                new_ctx->files[i]->ref_count++;
            }
        }

        for(u64 start = new_ctx->mms[MM_SEG_DATA].start; start < new_ctx->mms[MM_SEG_DATA].next_free; start += PAGE_SIZE){
            put_page_here(new_pgd, ctx->pgd, start);
        }

        for(u64 start = new_ctx->mms[MM_SEG_STACK].end - PAGE_SIZE; start >= new_ctx->mms[MM_SEG_STACK].start; start -= PAGE_SIZE){
            put_page_here(new_pgd, ctx->pgd, start);
        }

        for(u64 start = new_ctx->mms[MM_SEG_RODATA].start; start < new_ctx->mms[MM_SEG_RODATA].next_free; start += PAGE_SIZE){
            put_page_here(new_pgd, ctx->pgd, start);
        }

        for(u64 start = new_ctx->mms[MM_SEG_CODE].start; start < new_ctx->mms[MM_SEG_CODE].next_free; start += PAGE_SIZE){
            put_page_here(new_pgd, ctx->pgd, start);
        }

        struct vm_area* vma = ctx->vm_area;
        struct vm_area* new_vma = os_alloc(sizeof(struct vm_area));
        *new_vma = *vma;
        new_ctx->vm_area = new_vma;
        while(vma->vm_next){
            vma = vma->vm_next;
            new_vma->vm_next = os_alloc(sizeof(struct vm_area));
            new_vma = new_vma->vm_next;
            *new_vma = *vma;
            for(u64 start = vma->vm_start; start < vma->vm_end; start += PAGE_SIZE){
                put_page_here(new_pgd, ctx->pgd, start);
            }
        }

        /*--------------------- Your code [end] ----------------*/

        /*
        * The remaining part must not be changed
        */
        copy_os_pts(ctx->pgd, new_ctx->pgd);
        do_file_fork(new_ctx);
        setup_child_context(new_ctx);
        return pid;
}



/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data) 
 * it is called when there is a CoW violation in these areas. 
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    u64 pgd_index = (vaddr >> 39) & MASK;
    u64 pud_index = (vaddr >> 30) & MASK;
    u64 pmd_index = (vaddr >> 21) & MASK;
    u64 pte_index = (vaddr >> 12) & MASK;

    u64 *pgd = (u64 *)osmap(current->pgd);
    if (!(pgd[pgd_index] & PTE_P)) {
        printk("pgd fault\n");
        return -1;
    }

    u64 *pud = (u64 *)osmap(pgd[pgd_index] >> 12);
    if (!(pud[pud_index] & PTE_P)) {
        printk("pud fault\n");
        return -1;
    }

    u64 *pmd = (u64 *)osmap(pud[pud_index] >> 12);
    if (!(pmd[pmd_index] & PTE_P)) {
        printk("pmd fault\n");
        return -1;
    }

    u64 *pte = (u64 *)osmap(pmd[pmd_index] >> 12);
    if (!(pte[pte_index] & PTE_P)) {
        printk("pte fault\n");
        return -1;
    }

    u32 page_pfn_number = (u32)(pte[pte_index] >> 12);
    if(get_pfn_refcount(page_pfn_number) == 1){
        pte[pte_index] = pte[pte_index] | 0x19;
        return 1;
    }else{
        put_pfn(page_pfn_number);
        u64 new_page = (u64)os_pfn_alloc(USER_REG);
        memcpy(osmap(new_page), osmap((u64)page_pfn_number), PAGE_SIZE);

        pte[pte_index] = (new_page << 12) | 0x19;
    }
    tlb_flush();
    return 1;
}


