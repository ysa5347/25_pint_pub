#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "vm/page.h"
#include "vm/frame.h"
#endif

extern struct lock filesys_lock;

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void)
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void)
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f)
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */

  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      sys_exit (-1); // terminate. no more wait, parent

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel");

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      sys_exit (-1); // terminate. no more wait, parent
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f)
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /* (3.1.5) a page fault in the kernel merely sets eax to 0xffffffff
   * and copies its former value into eip */
  if(!user) { // kernel mode
    f->eip = (void *) f->eax;
    f->eax = 0xffffffff;
    return;
  }

#ifdef USERPROG
  /* VM: Handle page fault for virtual memory */
  struct thread *cur = thread_current ();
  struct page *page = NULL;
  
  /* Check if fault address is in user space */
  if (!is_user_vaddr (fault_addr)){
    // printf ("Page fault: invalid user address %p\n", fault_addr);
    goto page_fault_exit;
  }
  
  /* Try to find the page in the page table */
  page = page_lookup (&cur->page_table, fault_addr);
  
  if (page != NULL)
  {
    /* Page exists in page table but not in memory - load it */
    // printf ("Page fault: loading existing page at %p\n", fault_addr);
    
    if (page_load (page))
    {
      /* Successfully loaded the page */
      // printf ("Page fault: successfully loaded page at %p\n", fault_addr);
      return;
    }
    else
    {
      /* Failed to load the page */
      // printf ("Page fault: failed to load existing page at %p\n", fault_addr);
      goto page_fault_exit;
    }
  }
  else
  {
    /* Page not found in page table - check if it's a valid stack access */
    // printf ("Page fault: checking stack access for %p (esp=%p)\n", fault_addr, f->esp);
    /* Check if this is a mmap region access before checking stack */
    struct mmap_entry *mmap_entry = NULL;

    /* Find mmap entry containing the fault address */
    if (!list_empty(&cur->mmap_list)) {
      struct list_elem *e;
      for (e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list); e = list_next(e))
      {
        struct mmap_entry *entry = list_entry(e, struct mmap_entry, elem);
        void *entry_start = entry->addr;
        void *entry_end = (uint8_t*)entry->addr + entry->length;
        
        /* Check if address falls within this mapping range */
        if (fault_addr >= entry_start && fault_addr < entry_end) {
          mmap_entry = entry;
          break;
        }
      }
    }
    if (mmap_entry != NULL)
    {
      /* This is a memory mapped file access - load the page from file */
      // printf ("Page fault: mmap access at %p (mapid=%d)\n", fault_addr, mmap_entry->mapid);
      
      void *page_addr = pg_round_down(fault_addr);
      off_t page_offset = (uint8_t*)page_addr - (uint8_t*)mmap_entry->addr;
      off_t file_offset = mmap_entry->offset + page_offset;
      
      /* Calculate how many bytes to read from file for this page */
      lock_acquire (&filesys_lock);
      off_t file_size = file_length(mmap_entry->file);
      lock_release (&filesys_lock);
      
      size_t file_bytes = 0;
      size_t zero_bytes = 0;
      
      if (file_offset < file_size)
      {
        file_bytes = file_size - file_offset;
        if (file_bytes > PGSIZE)
          file_bytes = PGSIZE;
        zero_bytes = PGSIZE - file_bytes;
      }
      else
      {
        /* Past end of file - zero page */
        file_bytes = 0;
        zero_bytes = PGSIZE;
      }
      
      /* Create a file-backed page */
      struct page *p = page_create_file(page_addr, mmap_entry->file, 
                                        file_offset, file_bytes, zero_bytes, true);
      if (p == NULL)
      {
        // printf ("Page fault: failed to create mmap page at %p\n", fault_addr);
        goto page_fault_exit;
      }
      
      /* Insert into page table */
      if (!page_insert (&cur->page_table, p))
      {
        // printf ("Page fault: failed to insert mmap page at %p\n", fault_addr);
        free (p);
        goto page_fault_exit;
      }
      
      /* Load the page immediately */
      if (!page_load (p))
      {
        // printf ("Page fault: failed to load mmap page at %p\n", fault_addr);
        page_delete (&cur->page_table, p);
        goto page_fault_exit;
      }
      
      // printf ("Page fault: successfully loaded mmap page at %p\n", fault_addr);
      return;
    }
    if (page_is_stack_access (fault_addr, f->esp))
    {
      /* Calculate current stack size to check limits */
      size_t current_stack_size = PHYS_BASE - pg_round_down(fault_addr);
      // printf ("Page fault: potential stack growth to size %zu bytes\n", current_stack_size);
      
      /* Check if we've reached stack size limit */
      if (current_stack_size > STACK_MAX_SIZE)
      {
        // printf ("Page fault: stack size limit exceeded (%zu > %d bytes)\n", current_stack_size, STACK_MAX_SIZE);
        goto page_fault_exit;
      }
      
      /* Additional validation: check if this is a reasonable stack growth */
      if (fault_addr < f->esp - STACK_HEURISTIC * 4)  /* More lenient for function calls */
      {
        // printf ("Page fault: stack access too far from ESP (%p vs %p, distance=%ld)\n", fault_addr, f->esp, (char*)f->esp - (char*)fault_addr);
        goto page_fault_exit;
      }
      
      /* Try to grow the stack */
      // printf ("Page fault: attempting to grow stack at %p\n", fault_addr);
      
      if (page_grow_stack (fault_addr))
      {
        /* Successfully grew the stack */
        // printf ("Page fault: successfully grew stack at %p\n", fault_addr);
        return;
      }
      else
      {
        /* Failed to grow the stack */
        // printf ("Page fault: failed to grow stack at %p\n", fault_addr);
        goto page_fault_exit;
      }
    }
    else
    {
      /* Invalid memory access - provide detailed error information */
      if (fault_addr < PHYS_BASE && fault_addr >= PHYS_BASE - STACK_MAX_SIZE)
      {
        // printf ("Page fault: invalid stack access at %p (esp=%p, distance=%ld)\n", fault_addr, f->esp, (char*)f->esp - (char*)fault_addr);
      }
      else if (fault_addr < (void*)0x08048000)  /* Below typical code segment */
      {
        // printf ("Page fault: access to low memory at %p (possible null pointer)\n", fault_addr);
      }
      else
      {
        // printf ("Page fault: invalid memory access at %p\n", fault_addr);
      }
      goto page_fault_exit;
    }
  }

page_fault_exit:
  /* VM page fault handling failed - terminate the process */
  /* printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
          */
  // printf ("  fault_addr=%p, esp=%p, eip=%p\n", fault_addr, f->esp, f->eip);
  
  /* Additional debugging information for stack-related faults */
  if (fault_addr < PHYS_BASE && fault_addr >= PHYS_BASE - STACK_MAX_SIZE)
  {
    // printf ("  Stack region access detected\n");
    // printf ("  Distance from ESP: %ld bytes\n", (char*)f->esp - (char*)fault_addr);
    // printf ("  Current stack top: %p\n", f->esp);
    
    /* Try to identify stack pages */
    struct hash_iterator iter;
    int stack_page_count = 0;
    void *lowest_stack_page = PHYS_BASE;
    
    hash_first (&iter, &cur->page_table);
    while (hash_next (&iter))
    {
      struct page *p = hash_entry (hash_cur (&iter), struct page, hash_elem);
      if (p->vaddr < PHYS_BASE && p->vaddr >= PHYS_BASE - STACK_MAX_SIZE)
      {
        stack_page_count++;
        if (p->vaddr < lowest_stack_page)
          lowest_stack_page = p->vaddr;
      }
    }
    
    // printf ("  Current stack pages: %d, lowest: %p\n", stack_page_count, lowest_stack_page);
    // printf ("  Current stack size: %zu bytes\n", PHYS_BASE - lowest_stack_page);
  }
  
  /* Kill the faulting process */
  kill (f);
  
#else
  /* Original non-VM code */
  // printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  kill (f);
#endif
}