#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include <stdbool.h>
#include "threads/palloc.h"
#include "threads/synch.h"

/* Forward declaration */
struct page;

/* Physical frame structure */
struct frame 
{
    void *base;                 /* Physical address of frame */
    struct page *page;          /* Page that owns this frame */
    struct thread *owner;       /* Thread that owns this frame */
    
    bool pinned;                /* Is frame pinned (cannot be evicted)? */
    
    struct list_elem elem;      /* Element in frame table list */
};

/* Frame table operations */
void frame_table_init (void);
void frame_table_destroy (void);

/* Frame allocation and deallocation */
void *frame_alloc (enum palloc_flags flags, struct page *page);
void frame_free (void *frame_addr);

/* Frame eviction */
bool frame_evict (void);
struct frame *frame_pick_victim (void);

/* Frame utilities */
struct frame *frame_lookup (void *frame_addr);
void frame_pin (void *frame_addr);
void frame_unpin (void *frame_addr);
bool frame_is_pinned (void *frame_addr);

/* Clock algorithm support */
void frame_set_accessed (struct frame *f, bool accessed);
bool frame_get_accessed (struct frame *f);

/* Statistics and debugging */
size_t frame_table_size (void);
void frame_table_print (void);

#endif /* vm/frame.h */