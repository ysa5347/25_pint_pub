#include "vm/swap.h"
#include <bitmap.h>
#include <debug.h>
#include <stdio.h>
#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

/* Swap device block */
static struct block *swap_device;

/* Swap slot bitmap - tracks which slots are in use */
static struct bitmap *swap_bitmap;

/* Total number of swap slots available */
static size_t swap_slot_count;

/* Lock for swap operations */
static struct lock swap_lock;

/* Statistics */
static size_t swap_reads;
static size_t swap_writes;

/* Initialize the swap system */
void 
swap_init (void)
{
    /* Get the swap block device */
    swap_device = block_get_role (BLOCK_SWAP);
    if (swap_device == NULL)
    {
        printf ("Warning: No swap device found, swapping disabled.\n");
        swap_slot_count = 0;
        swap_bitmap = NULL;
        return;
    }
    
    /* Calculate number of swap slots */
    block_sector_t swap_size = block_size (swap_device);
    swap_slot_count = swap_size / SECTORS_PER_PAGE;
    
    printf ("Swap device found: %s, %zu pages\n", 
            block_name (swap_device), swap_slot_count);
    
    /* Create bitmap to track swap slot usage */
    swap_bitmap = bitmap_create (swap_slot_count);
    if (swap_bitmap == NULL)
        PANIC ("Failed to create swap bitmap");
    
    /* Initialize lock and statistics */
    lock_init (&swap_lock);
    swap_reads = 0;
    swap_writes = 0;
}

/* Destroy the swap system */
void 
swap_destroy (void)
{
    if (swap_bitmap != NULL)
    {
        bitmap_destroy (swap_bitmap);
        swap_bitmap = NULL;
    }
    
    swap_device = NULL;
    swap_slot_count = 0;
}

/* Allocate a swap slot */
swap_slot_t 
swap_alloc (void)
{
    if (swap_device == NULL || swap_bitmap == NULL)
        return SWAP_SLOT_INVALID;
    
    lock_acquire (&swap_lock);
    
    /* Find a free slot */
    size_t slot = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
    
    lock_release (&swap_lock);
    
    if (slot == BITMAP_ERROR)
        return SWAP_SLOT_INVALID;
    
    return slot;
}

/* Free a swap slot */
void 
swap_free (swap_slot_t slot)
{
    if (swap_device == NULL || swap_bitmap == NULL)
        return;
    
    ASSERT (swap_is_valid_slot (slot));
    
    lock_acquire (&swap_lock);
    
    /* Mark slot as free */
    ASSERT (bitmap_test (swap_bitmap, slot));
    bitmap_set (swap_bitmap, slot, false);
    
    lock_release (&swap_lock);
}

/* Swap out a page to disk and return the swap slot */
swap_slot_t 
swap_out (void *page)
{
    ASSERT (page != NULL);
    ASSERT (pg_ofs (page) == 0);  /* Page must be page-aligned */
    
    if (swap_device == NULL)
        return SWAP_SLOT_INVALID;
    
    /* Allocate a swap slot */
    swap_slot_t slot = swap_alloc ();
    if (slot == SWAP_SLOT_INVALID)
        return SWAP_SLOT_INVALID;
    
    /* Write page to swap device */
    block_sector_t sector = slot * SECTORS_PER_PAGE;
    int i;
    for (i = 0; i < SECTORS_PER_PAGE; i++)
    {
        block_write (swap_device, sector + i, 
                    (char *) page + i * BLOCK_SECTOR_SIZE);
    }
    
    lock_acquire (&swap_lock);
    swap_writes++;
    lock_release (&swap_lock);
    
    return slot;
}

/* Swap in a page from disk */
bool 
swap_in (swap_slot_t slot, void *page)
{
    ASSERT (page != NULL);
    ASSERT (pg_ofs (page) == 0);  /* Page must be page-aligned */
    
    if (swap_device == NULL || !swap_is_valid_slot (slot))
        return false;
    
    lock_acquire (&swap_lock);
    
    /* Check if slot is actually in use */
    if (!bitmap_test (swap_bitmap, slot))
    {
        lock_release (&swap_lock);
        PANIC ("Attempting to swap in from free slot %zu", slot);
    }
    
    lock_release (&swap_lock);
    
    /* Read page from swap device */
    block_sector_t sector = slot * SECTORS_PER_PAGE;
    int i;
    for (i = 0; i < SECTORS_PER_PAGE; i++)
    {
        block_read (swap_device, sector + i, 
                   (char *) page + i * BLOCK_SECTOR_SIZE);
    }
    
    lock_acquire (&swap_lock);
    swap_reads++;
    lock_release (&swap_lock);
    
    /* Free the swap slot after reading */
    swap_free (slot);
    
    return true;
}

/* Check if a swap slot is valid */
bool 
swap_is_valid_slot (swap_slot_t slot)
{
    return slot != SWAP_SLOT_INVALID && slot < swap_slot_count;
}

/* Get total number of swap slots */
size_t 
swap_total_slots (void)
{
    return swap_slot_count;
}

/* Get number of used swap slots */
size_t 
swap_used_slots (void)
{
    if (swap_bitmap == NULL)
        return 0;
    
    lock_acquire (&swap_lock);
    size_t used = bitmap_count (swap_bitmap, 0, swap_slot_count, true);
    lock_release (&swap_lock);
    
    return used;
}

/* Get number of free swap slots */
size_t 
swap_free_slots (void)
{
    return swap_total_slots () - swap_used_slots ();
}

/* Print swap statistics */
void 
swap_print_stats (void)
{
    if (swap_device == NULL)
    {
        printf ("Swap: disabled\n");
        return;
    }
    
    lock_acquire (&swap_lock);
    
    printf ("Swap statistics:\n");
    printf ("  Device: %s\n", block_name (swap_device));
    printf ("  Total slots: %zu\n", swap_slot_count);
    printf ("  Used slots: %zu\n", swap_used_slots ());
    printf ("  Free slots: %zu\n", swap_free_slots ());
    printf ("  Reads: %zu\n", swap_reads);
    printf ("  Writes: %zu\n", swap_writes);
    
    lock_release (&swap_lock);
}