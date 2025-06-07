#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"

/* Swap slot index type */
typedef size_t swap_slot_t;

/* Invalid swap slot value */
#define SWAP_SLOT_INVALID SIZE_MAX

/* Number of sectors per page */
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

/* Swap table operations */
void swap_init (void);
void swap_destroy (void);

/* Swap slot allocation/deallocation */
swap_slot_t swap_alloc (void);
void swap_free (swap_slot_t slot);

/* Swap I/O operations */
swap_slot_t swap_out (void *page);
bool swap_in (swap_slot_t slot, void *page);

/* Swap utilities */
bool swap_is_valid_slot (swap_slot_t slot);
size_t swap_total_slots (void);
size_t swap_used_slots (void);
size_t swap_free_slots (void);

/* Statistics and debugging */
void swap_print_stats (void);

#endif /* vm/swap.h */