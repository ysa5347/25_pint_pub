#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "filesys/off_t.h"

/* Forward declarations */
struct file;

/* Memory mapping identifier type */
typedef int mapid_t;
#define MAP_FAILED ((mapid_t) -1)

/* Memory mapping entry structure */
struct mmap_entry
{
    mapid_t mapid;              /* Mapping identifier */
    void *addr;                 /* Start virtual address */
    size_t length;              /* Length of mapping in bytes */
    struct file *file;          /* File being mapped */
    off_t offset;               /* Offset in file */
    struct list_elem elem;      /* List element for process mmap list */
};

void syscall_init (void);
void sys_exit (int);

/* Memory mapping functions */
mapid_t sys_mmap (int fd, void *addr);
void sys_munmap (mapid_t mapping);

#endif /* userprog/syscall.h */