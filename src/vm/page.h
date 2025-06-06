#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <list.h>
#include <stdbool.h>
#include <stdint.h>
#include "filesys/file.h"
#include "threads/synch.h"

/* Page types */
enum page_type 
{
    PAGE_FILE,    /* Page backed by file */
    PAGE_SWAP,    /* Page backed by swap */
    PAGE_ZERO     /* Page filled with zeros */
};

/* Page states */
enum page_state
{
    PAGE_MEMORY,  /* Page is in physical memory */
    PAGE_SWAPPED, /* Page is swapped out */
    PAGE_FILESYS  /* Page is in file system (not loaded yet) */
};

/* Virtual page structure */
struct page 
{
    void *vaddr;                /* Virtual address (user page) */
    enum page_type type;        /* Type of page */
    enum page_state state;      /* Current state of page */
    
    bool writable;              /* Is page writable? */
    bool dirty;                 /* Has page been modified? */
    bool accessed;              /* Has page been accessed? (for LRU) */
    
    /* File-backed page information */
    struct file *file;          /* File this page is backed by */
    off_t file_offset;          /* Offset in file */
    size_t file_bytes;          /* Bytes to read from file */
    size_t zero_bytes;          /* Bytes to zero after reading */
    
    /* Swap information */
    size_t swap_slot;           /* Swap slot number if swapped */
    
    /* Frame information */
    void *frame;                /* Physical frame address if in memory */
    
    /* Hash table element */
    struct hash_elem hash_elem; /* Element in page table hash */
    
    /* Lock for synchronization */
    struct lock page_lock;      /* Lock for this page */
};

/* Page table operations */
void page_table_init (struct hash *page_table);
void page_table_destroy (struct hash *page_table);

/* Page creation and management */
struct page *page_create (void *vaddr, enum page_type type, bool writable);
struct page *page_lookup (struct hash *page_table, void *vaddr);
bool page_insert (struct hash *page_table, struct page *p);
void page_delete (struct hash *page_table, struct page *p);

/* Page loading and unloading */
bool page_load (struct page *p);
bool page_load_file (struct page *p);
bool page_load_swap (struct page *p);
bool page_load_zero (struct page *p);

/* Page file operations */
struct page *page_create_file (void *vaddr, struct file *file, 
                              off_t offset, size_t file_bytes, 
                              size_t zero_bytes, bool writable);

/* Page swap operations */
bool page_swap_out (struct page *p);
bool page_swap_in (struct page *p);

/* Page utility functions */
bool page_set_frame (struct page *p, void *frame);
void page_clear_frame (struct page *p);
bool page_is_loaded (struct page *p);

/* Hash table helper functions */
unsigned page_hash (const struct hash_elem *e, void *aux);
bool page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
void page_destroy_func (struct hash_elem *e, void *aux);

/* Stack growth */
bool page_is_stack_access (void *vaddr, void *esp);
bool page_grow_stack (void *vaddr);

/* Constants */
#define STACK_MAX_SIZE (8 * 1024 * 1024)  /* 8MB stack limit */
#define STACK_HEURISTIC 32                 /* Stack access heuristic */

#endif /* vm/page.h */