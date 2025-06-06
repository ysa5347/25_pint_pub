#include "vm/frame.h"
#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"

/* Frame table - list of all allocated frames */
static struct list frame_table;

/* Lock for frame table operations */
static struct lock frame_table_lock;

/* Clock algorithm pointer - points to next frame to consider for eviction */
static struct list_elem *clock_hand;

/* Initialize the frame table */
void 
frame_table_init (void)
{
    list_init (&frame_table);
    lock_init (&frame_table_lock);
    clock_hand = NULL;
}

/* Destroy the frame table */
void 
frame_table_destroy (void)
{
    lock_acquire (&frame_table_lock);
    
    /* Free all frames */
    while (!list_empty (&frame_table))
    {
        struct list_elem *e = list_pop_front (&frame_table);
        struct frame *f = list_entry (e, struct frame, elem);
        palloc_free_page (f->base);
        free (f);
    }
    
    clock_hand = NULL;
    lock_release (&frame_table_lock);
}

/* Allocate a new frame */
void *
frame_alloc (enum palloc_flags flags, struct page *page)
{
    /* Try to allocate a page from palloc */
    void *frame_addr = palloc_get_page (flags);
    
    /* If allocation failed, try to evict a frame */
    if (frame_addr == NULL)
    {
        if (!frame_evict ())
            return NULL;
        
        /* Try allocation again */
        frame_addr = palloc_get_page (flags);
        if (frame_addr == NULL)
            return NULL;
    }
    
    /* Create frame structure */
    struct frame *f = malloc (sizeof (struct frame));
    if (f == NULL)
    {
        palloc_free_page (frame_addr);
        return NULL;
    }
    
    /* Initialize frame */
    f->base = frame_addr;
    f->page = page;
    f->owner = thread_current ();
    f->pinned = false;
    
    /* Add to frame table */
    lock_acquire (&frame_table_lock);
    list_push_back (&frame_table, &f->elem);
    
    /* Initialize clock hand if this is the first frame */
    if (clock_hand == NULL)
        clock_hand = &f->elem;
    
    lock_release (&frame_table_lock);
    
    return frame_addr;
}

/* Free a frame */
void 
frame_free (void *frame_addr)
{
    if (frame_addr == NULL)
        return;
    
    lock_acquire (&frame_table_lock);
    
    /* Find the frame in the table */
    struct frame *f = frame_lookup (frame_addr);
    if (f == NULL)
    {
        lock_release (&frame_table_lock);
        return;
    }
    
    /* Update clock hand if it points to this frame */
    if (clock_hand == &f->elem)
    {
        if (list_size (&frame_table) > 1)
            clock_hand = list_next (clock_hand);
        else
            clock_hand = NULL;
    }
    
    /* Remove from frame table */
    list_remove (&f->elem);
    
    lock_release (&frame_table_lock);
    
    /* Free the physical page and frame structure */
    palloc_free_page (frame_addr);
    free (f);
}

/* Evict a frame using clock algorithm */
bool 
frame_evict (void)
{
    lock_acquire (&frame_table_lock);
    
    if (list_empty (&frame_table))
    {
        lock_release (&frame_table_lock);
        return false;
    }
    
    /* Find a victim frame */
    struct frame *victim = frame_pick_victim ();
    if (victim == NULL)
    {
        lock_release (&frame_table_lock);
        return false;
    }
    
    /* Don't evict pinned frames */
    if (victim->pinned)
    {
        lock_release (&frame_table_lock);
        return false;
    }
    
    lock_release (&frame_table_lock);
    
    /* Swap out the victim page */
    struct page *victim_page = victim->page;
    if (victim_page != NULL)
    {
        /* Check if page is dirty */
        bool dirty = pagedir_is_dirty (victim->owner->pagedir, victim_page->vaddr);
        
        /* If page is dirty or writable, save to swap */
        if (dirty || victim_page->writable)
        {
            if (!page_swap_out (victim_page))
                return false;
        }
        else
        {
            /* Clean page can be discarded */
            pagedir_clear_page (victim->owner->pagedir, victim_page->vaddr);
            victim_page->frame = NULL;
            victim_page->state = PAGE_FILESYS;
        }
    }
    
    /* Free the frame */
    frame_free (victim->base);
    
    return true;
}

/* Pick a victim frame using clock algorithm (Second Chance) */
struct frame *
frame_pick_victim (void)
{
    if (list_empty (&frame_table))
        return NULL;
    
    size_t table_size = list_size (&frame_table);
    size_t iterations = 0;
    
    /* Clock algorithm: scan through frames looking for one with accessed = false */
    while (iterations < table_size * 2)  /* At most 2 full scans */
    {
        /* Move to next frame */
        if (clock_hand == NULL || clock_hand == list_end (&frame_table))
            clock_hand = list_begin (&frame_table);
        
        struct frame *f = list_entry (clock_hand, struct frame, elem);
        
        /* Skip pinned frames */
        if (f->pinned)
        {
            clock_hand = list_next (clock_hand);
            iterations++;
            continue;
        }
        
        /* Check accessed bit */
        bool accessed = false;
        if (f->page != NULL && f->owner != NULL)
        {
            accessed = pagedir_is_accessed (f->owner->pagedir, f->page->vaddr);
        }
        
        if (!accessed)
        {
            /* Found victim - frame with accessed bit = false */
            return f;
        }
        else
        {
            /* Give second chance - clear accessed bit */
            if (f->page != NULL && f->owner != NULL)
            {
                pagedir_set_accessed (f->owner->pagedir, f->page->vaddr, false);
            }
        }
        
        clock_hand = list_next (clock_hand);
        iterations++;
    }
    
    /* If no victim found after 2 scans, return current frame */
    if (clock_hand != NULL && clock_hand != list_end (&frame_table))
    {
        struct frame *f = list_entry (clock_hand, struct frame, elem);
        if (!f->pinned)
            return f;
    }
    
    return NULL;
}

/* Look up a frame by its physical address */
struct frame *
frame_lookup (void *frame_addr)
{
    struct list_elem *e;
    
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e))
    {
        struct frame *f = list_entry (e, struct frame, elem);
        if (f->base == frame_addr)
            return f;
    }
    
    return NULL;
}

/* Pin a frame (prevent it from being evicted) */
void 
frame_pin (void *frame_addr)
{
    lock_acquire (&frame_table_lock);
    
    struct frame *f = frame_lookup (frame_addr);
    if (f != NULL)
        f->pinned = true;
    
    lock_release (&frame_table_lock);
}

/* Unpin a frame (allow it to be evicted) */
void 
frame_unpin (void *frame_addr)
{
    lock_acquire (&frame_table_lock);
    
    struct frame *f = frame_lookup (frame_addr);
    if (f != NULL)
        f->pinned = false;
    
    lock_release (&frame_table_lock);
}

/* Check if a frame is pinned */
bool 
frame_is_pinned (void *frame_addr)
{
    lock_acquire (&frame_table_lock);
    
    struct frame *f = frame_lookup (frame_addr);
    bool pinned = (f != NULL) ? f->pinned : false;
    
    lock_release (&frame_table_lock);
    
    return pinned;
}

/* Set accessed bit for a frame */
void 
frame_set_accessed (struct frame *f, bool accessed)
{
    if (f != NULL && f->page != NULL && f->owner != NULL)
    {
        pagedir_set_accessed (f->owner->pagedir, f->page->vaddr, accessed);
    }
}

/* Get accessed bit for a frame */
bool 
frame_get_accessed (struct frame *f)
{
    if (f != NULL && f->page != NULL && f->owner != NULL)
    {
        return pagedir_is_accessed (f->owner->pagedir, f->page->vaddr);
    }
    return false;
}

/* Get number of frames in the table */
size_t 
frame_table_size (void)
{
    lock_acquire (&frame_table_lock);
    size_t size = list_size (&frame_table);
    lock_release (&frame_table_lock);
    
    return size;
}

/* Print frame table for debugging */
void 
frame_table_print (void)
{
    lock_acquire (&frame_table_lock);
    
    printf ("Frame table (%zu frames):\n", list_size (&frame_table));
    
    struct list_elem *e;
    int i = 0;
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e))
    {
        struct frame *f = list_entry (e, struct frame, elem);
        printf ("  [%d] base=%p, page=%p, owner=%s, pinned=%s\n",
                i++, f->base, f->page, 
                f->owner ? f->owner->name : "NULL",
                f->pinned ? "yes" : "no");
    }
    
    lock_release (&frame_table_lock);
}