#include "vm/page.h"
#include <string.h>
#include <stdio.h>
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "vm/swap.h"

/* Initialize page table */
void 
page_table_init (struct hash *page_table)
{
    /* Thread 초기화 시점에서는 hash table을 초기화하지 않고
       단순히 NULL 상태로만 설정 */
    ASSERT (page_table != NULL);
    memset (page_table, 0, sizeof (*page_table));
}

/* Destroy page table and all pages in it */
void 
page_table_destroy (struct hash *page_table)
{
    if (page_table != NULL && page_table->buckets != NULL) 
        hash_destroy (page_table, page_destroy_func);
}

/* Create a new page */
struct page *
page_create (void *vaddr, enum page_type type, bool writable)
{
    struct page *p = malloc (sizeof (struct page));
    if (p == NULL)
        return NULL;
    
    p->vaddr = pg_round_down (vaddr);
    p->type = type;
    p->state = PAGE_FILESYS;
    p->writable = writable;
    p->dirty = false;
    p->accessed = false;
    
    p->file = NULL;
    p->file_offset = 0;
    p->file_bytes = 0;
    p->zero_bytes = 0;
    
    p->swap_slot = SIZE_MAX;
    p->frame = NULL;
    
    lock_init (&p->page_lock);
    
    return p;
}

/* Look up a page in the page table */
struct page *
page_lookup (struct hash *page_table, void *vaddr)
{
    if (page_table->buckets == NULL)
        hash_init (page_table, page_hash, page_less, NULL);

    struct page p;
    struct hash_elem *e;
    
    p.vaddr = pg_round_down (vaddr);
    e = hash_find (page_table, &p.hash_elem);
    
    return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}

/* Insert a page into the page table */
bool 
page_insert (struct hash *page_table, struct page *p)
{
    if (page_table->buckets == NULL)
        hash_init (page_table, page_hash, page_less, NULL);
        
    struct hash_elem *e = hash_insert (page_table, &p->hash_elem);
    return e == NULL;  /* True if insertion was successful */
}

/* Delete a page from the page table */
void 
page_delete (struct hash *page_table, struct page *p)
{
    hash_delete (page_table, &p->hash_elem);
    
    /* Free the physical frame if allocated */
    if (p->frame != NULL)
        frame_free (p->frame);
    
    /* Free swap slot if used */
    if (p->state == PAGE_SWAPPED && p->swap_slot != SIZE_MAX)
        swap_free (p->swap_slot);
    
    free (p);
}

/* Load a page into physical memory */
bool 
page_load (struct page *p)
{
    if (p == NULL)
        return false;
    
    lock_acquire (&p->page_lock);
    
    /* Check if page is already loaded */
    if (p->state == PAGE_MEMORY)
    {
        lock_release (&p->page_lock);
        return true;
    }
    
    bool success = false;
    
    /* Load based on page type and current state */
    switch (p->type)
    {
        case PAGE_FILE:
            success = page_load_file (p);
            break;
        case PAGE_SWAP:
            success = page_load_swap (p);
            break;
        case PAGE_ZERO:
            success = page_load_zero (p);
            break;
        default:
            success = false;
            break;
    }
    
    lock_release (&p->page_lock);
    return success;
}

/* Load a file-backed page */
bool 
page_load_file (struct page *p)
{
    /* Get a frame for this page */
    void *frame = frame_alloc (PAL_USER, p);
    if (frame == NULL)
        return false;
    
    /* Read file content into frame */
    if (p->file != NULL && p->file_bytes > 0)
    {
        file_seek (p->file, p->file_offset);
        int bytes_read = file_read (p->file, frame, p->file_bytes);
        if (bytes_read != (int) p->file_bytes)
        {
            frame_free (frame);
            return false;
        }
    }
    
    /* Zero the remaining bytes */
    if (p->zero_bytes > 0)
        memset ((char *) frame + p->file_bytes, 0, p->zero_bytes);
    
    /* Install page in page table */
    if (!install_page (p->vaddr, frame, p->writable))
    {
        frame_free (frame);
        return false;
    }
    
    p->frame = frame;
    p->state = PAGE_MEMORY;
    return true;
}

/* Load a swapped page */
bool 
page_load_swap (struct page *p)
{
    if (p->state != PAGE_SWAPPED)
        return false;
    
    /* Get a frame for this page */
    void *frame = frame_alloc (PAL_USER, p);
    if (frame == NULL)
        return false;
    
    /* Read from swap */
    if (!swap_in (p->swap_slot, frame))
    {
        frame_free (frame);
        return false;
    }
    
    /* Install page in page table */
    if (!install_page (p->vaddr, frame, p->writable))
    {
        frame_free (frame);
        return false;
    }
    
    p->frame = frame;
    p->state = PAGE_MEMORY;
    p->swap_slot = SIZE_MAX;
    
    return true;
}

/* Load a zero-filled page */
bool 
page_load_zero (struct page *p)
{
    /* Get a frame for this page */
    void *frame = frame_alloc (PAL_ZERO | PAL_USER, p);
    if (frame == NULL)
        return false;
    
    /* Install page in page table */
    if (!install_page (p->vaddr, frame, p->writable))
    {
        frame_free (frame);
        return false;
    }
    
    p->frame = frame;
    p->state = PAGE_MEMORY;
    return true;
}

/* Create a file-backed page */
struct page *
page_create_file (void *vaddr, struct file *file, off_t offset, 
                 size_t file_bytes, size_t zero_bytes, bool writable)
{
    struct page *p = page_create (vaddr, PAGE_FILE, writable);
    if (p == NULL)
        return NULL;
    
    p->file = file;
    p->file_offset = offset;
    p->file_bytes = file_bytes;
    p->zero_bytes = zero_bytes;
    
    return p;
}

/* Swap out a page */
bool 
page_swap_out (struct page *p)
{
    if (p->state != PAGE_MEMORY || p->frame == NULL)
        return false;
    
    lock_acquire (&p->page_lock);
    
    /* Allocate swap slot */
    size_t slot = swap_out (p->frame);
    if (slot == SIZE_MAX)
    {
        lock_release (&p->page_lock);
        return false;
    }
    
    /* Update page information */
    p->swap_slot = slot;
    p->state = PAGE_SWAPPED;
    p->type = PAGE_SWAP;
    
    /* Remove from page table and free frame */
    pagedir_clear_page (thread_current()->pagedir, p->vaddr);
    frame_free (p->frame);
    p->frame = NULL;
    
    lock_release (&p->page_lock);
    return true;
}

/* Swap in a page */
bool 
page_swap_in (struct page *p)
{
    if (p->state != PAGE_SWAPPED)
        return false;
    
    return page_load_swap (p);
}

/* Set frame for a page */
bool 
page_set_frame (struct page *p, void *frame)
{
    if (p == NULL || frame == NULL)
        return false;
    
    p->frame = frame;
    p->state = PAGE_MEMORY;
    return true;
}

/* Clear frame from a page */
void 
page_clear_frame (struct page *p)
{
    if (p != NULL)
    {
        p->frame = NULL;
        p->state = (p->type == PAGE_SWAP) ? PAGE_SWAPPED : PAGE_FILESYS;
    }
}

/* Check if page is loaded in memory */
bool 
page_is_loaded (struct page *p)
{
    return p != NULL && p->state == PAGE_MEMORY && p->frame != NULL;
}

/* Hash function for pages */
unsigned 
page_hash (const struct hash_elem *e, void *aux UNUSED)
{
    struct page *p = hash_entry (e, struct page, hash_elem);
    return hash_bytes (&p->vaddr, sizeof (p->vaddr));
}

/* Comparison function for pages */
bool 
page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct page *page_a = hash_entry (a, struct page, hash_elem);
    struct page *page_b = hash_entry (b, struct page, hash_elem);
    
    return page_a->vaddr < page_b->vaddr;
}

/* Destroy function for hash table cleanup */
void 
page_destroy_func (struct hash_elem *e, void *aux UNUSED)
{
    struct page *p = hash_entry (e, struct page, hash_elem);
    
    /* Free the physical frame if allocated */
    if (p->frame != NULL)
        frame_free (p->frame);
    
    /* Free swap slot if used */
    if (p->state == PAGE_SWAPPED && p->swap_slot != SIZE_MAX)
        swap_free (p->swap_slot);
    
    free (p);
}

/* Check if a memory access is a valid stack access */
bool 
page_is_stack_access (void *vaddr, void *esp)
{
    return (vaddr >= esp || 
            vaddr >= (char *) esp - STACK_HEURISTIC) &&
           vaddr >= PHYS_BASE - STACK_MAX_SIZE;
}

/* Grow the stack by creating a new page */
bool 
page_grow_stack (void *vaddr)
{
    /* Check if we're within stack size limit */
    if (vaddr < PHYS_BASE - STACK_MAX_SIZE)
        return false;
    
    /* Round down to page boundary */
    void *page_addr = pg_round_down (vaddr);
    
    /* Create a new zero-filled page */
    struct page *p = page_create (page_addr, PAGE_ZERO, true);
    if (p == NULL)
        return false;
    
    /* Insert into current thread's page table */
    struct thread *cur = thread_current ();
    if (!page_insert (&cur->page_table, p))
    {
        free (p);
        return false;
    }
    
    /* Load the page immediately */
    return page_load (p);
}