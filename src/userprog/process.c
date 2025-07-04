#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "vm/page.h"
#include "vm/swap.h"
#endif

#ifdef DEBUG
#define _DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
#define _DEBUG_PRINTF(...) /* do nothing */
#endif

extern struct lock filesys_lock; 

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void push_arguments (const char *[], int cnt, void **esp);

/* Starts a new thread running a user program loaded from
   `cmdline`. The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
pid_t
process_execute (const char *cmdline)
{
  char *cmdline_copy = NULL, *file_name = NULL;
  char *save_ptr = NULL;
  struct process_control_block *pcb = NULL;
  tid_t tid;

  /* Make a copy of CMD_LINE.
     Otherwise there's a race between the caller and load(). */
  cmdline_copy = palloc_get_page (0);
  if (cmdline_copy == NULL) {
    goto execute_failed;
  }
  strlcpy (cmdline_copy, cmdline, PGSIZE);

  // Extract file_name from cmdline. Should make a copy.
  file_name = palloc_get_page (0);
  if (file_name == NULL) {
    goto execute_failed;
  }
  strlcpy (file_name, cmdline, PGSIZE);
  file_name = strtok_r(file_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */

  // Create a PCB, along with file_name, and pass it into thread_create
  // so that a newly created thread can hold the PCB of process to be executed.
  pcb = palloc_get_page(0);
  if (pcb == NULL) {
    goto execute_failed;
  }

  // pid is not set yet. Later, in start_process(), it will be determined.
  // so we have to postpone afterward actions (such as putting 'pcb'
  // alongwith (determined) 'pid' into 'child_list'), using context switching.
  pcb->pid = PID_INITIALIZING;

  pcb->cmdline = cmdline_copy;
  pcb->waiting = false;
  pcb->exited = false;
  pcb->orphan = false;
  pcb->exitcode = -1; // undefined

  sema_init(&pcb->sema_initialization, 0);
  sema_init(&pcb->sema_wait, 0);

  // create thread!
  tid = thread_create (file_name, PRI_DEFAULT, start_process, pcb);

  if (tid == TID_ERROR) {
    goto execute_failed;
  }

  // wait until initialization inside start_process() is complete.
  sema_down(&pcb->sema_initialization);
  if(cmdline_copy) {
    palloc_free_page (cmdline_copy);
  }

  // process successfully created, maintain child process list
  if(pcb->pid >= 0) {
    list_push_back (&(thread_current()->child_list), &(pcb->elem));
  }

  palloc_free_page (file_name);
  return pcb->pid;

execute_failed:
  // release allocated memory and return
  if(cmdline_copy) palloc_free_page (cmdline_copy);
  if(file_name) palloc_free_page (file_name);
  if(pcb) palloc_free_page (pcb);

  return PID_ERROR;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *pcb_)
{
  struct thread *t = thread_current();
  struct process_control_block *pcb = pcb_;

  char *file_name = (char*) pcb->cmdline;
  bool success = false;

  // cmdline handling
  const char **cmdline_tokens = (const char**) palloc_get_page(0);

  struct intr_frame if_;
  if (cmdline_tokens == NULL){
    printf("[Error] Kernel Error: Not enough memory\n");
  }
  else{
    char* save_ptr;
    char* token=strtok_r(file_name, " ", &save_ptr);
    int cnt = 0;
    while(token!=NULL){
      cmdline_tokens[cnt++]=token;
      token=strtok_r(NULL, " ", &save_ptr);
    }

    /* Initialize interrupt frame and load executable. */
    memset (&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load (file_name, &if_.eip, &if_.esp);
    if (success) {
      //push_arguments (cmdline_tokens, cnt, &if_.esp);
      ASSERT(cnt >= 0);
      int i, len = 0;
      void* argv_addr[cnt];
      for (i = 0; i < cnt; i++) {
        len = strlen(cmdline_tokens[i]) + 1;
        if_.esp -= len;
        memcpy(if_.esp, cmdline_tokens[i], len);
        argv_addr[i] = if_.esp;
      }

      // word align
      if_.esp = (void*)((unsigned int)(if_.esp) & 0xfffffffc);

      // last null
      if_.esp -= 4;
      *((uint32_t*) if_.esp) = 0;

      // setting **esp with argvs
      for (i = cnt - 1; i >= 0; i--) {
        if_.esp -= 4;
        *((void**) if_.esp) = argv_addr[i];
      }

      // setting **argv (addr of stack, esp)
      if_.esp -= 4;
      *((void**) if_.esp) = (if_.esp + 4);

      // setting argc
      if_.esp -= 4;
      *((int*) if_.esp) = cnt;

      // setting ret addr
      if_.esp -= 4;
      *((int*) if_.esp) = 0;
    }
    palloc_free_page (cmdline_tokens);
  }

  /* Assign PCB */
  // we maintain an one-to-one mapping between pid and tid, with identity function.
  // pid is determined, so interact with process_execute() for maintaining child_list
  if(success) pcb->pid=(pid_t)(t->tid);
  else pcb->pid=PID_ERROR;
  t->pcb = pcb;

  // wake up sleeping in process_execute()
  sema_up(&pcb->sema_initialization);

  /* If load failed, quit. */
  if (!success)
    sys_exit (-1);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct thread *t = thread_current ();
  struct list *child_list = &(t->child_list);

  // lookup the process with tid equals 'child_tid' from 'child_list'
  struct process_control_block *child_pcb = NULL;
  struct list_elem *it = NULL;

  if (!list_empty(child_list)) {
    for (it = list_front(child_list); it != list_end(child_list); it = list_next(it)) {
      struct process_control_block *pcb = list_entry(
          it, struct process_control_block, elem);

      if(pcb->pid == child_tid) { // OK, the direct child found
        child_pcb = pcb;
        break;
      }
    }
  }

  // if child process is not found, return -1 immediately
  if (child_pcb == NULL) return -1;
  
  // already waiting (the parent already called wait on child's pid)
  if (child_pcb->waiting) return -1; // a process may wait for any fixed child at most once
  else child_pcb->waiting = true;

  // wait(block) until child terminates
  // see process_exit() for signaling this semaphore
  if (! child_pcb->exited) sema_down(& (child_pcb->sema_wait));
  
  ASSERT (child_pcb->exited == true);

  // remove from child_list
  ASSERT (it != NULL);
  list_remove (it);

  // return the exit code of the child process
  int retcode = child_pcb->exitcode;

  // Now the pcb object of the child process can be finally freed.
  // (in this context, the child process is guaranteed to have been exited)
  palloc_free_page(child_pcb);

  return retcode;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Resources should be cleaned up */
  // 1. file descriptors
  struct list *fdlist = &cur->file_descriptors;
  while (!list_empty(fdlist)) {
    struct list_elem *e = list_pop_front (fdlist);
    struct file_desc *desc = list_entry(e, struct file_desc, elem);
    file_close(desc->file);
    palloc_free_page(desc); // see sys_open()
  }

  // 2. clean up pcb object of all children processes
  struct list *child_list = &cur->child_list;
  while (!list_empty(child_list)) {
    struct list_elem *e = list_pop_front (child_list);
    struct process_control_block *pcb;
    pcb = list_entry(e, struct process_control_block, elem);
    if (pcb->exited == true) {
      // pcb can freed when it is already terminated
      palloc_free_page (pcb);
    } else {
      // the child process becomes an orphan.
      // do not free pcb yet, postpone until the child terminates
      pcb->orphan = true;
    }
  }

  while (!list_empty(&cur->mmap_list)) {
    struct list_elem *e = list_front(&cur->mmap_list);
    struct mmap_entry *entry = list_entry(e, struct mmap_entry, elem);
    mapid_t mapid = entry->mapid;
    
    /* Try to unmap normally first */
    sys_munmap(mapid);
    
    /* Safety check: if munmap failed and entry is still there, force remove */
    if (!list_empty(&cur->mmap_list)) {
      struct list_elem *check_e = list_front(&cur->mmap_list);
      struct mmap_entry *check_entry = list_entry(check_e, struct mmap_entry, elem);
      
      if (check_entry == entry) {
        /* munmap failed - force cleanup */
        printf("[WARNING] Force cleaning mmap entry (mapid=%d) due to munmap failure\n", entry->mapid);
        
        /* Remove from list */
        list_remove(&entry->elem);
        
        /* Force close file if still open */
        if (entry->file) {
          lock_acquire (&filesys_lock);
          file_close(entry->file);
          lock_release (&filesys_lock);
        }
        
        /* Free memory */
        palloc_free_page(entry);
      }
    }
  }
  
  /* Release file for the executable */
  if(cur->executing_file) {
    file_allow_write(cur->executing_file);
    file_close(cur->executing_file);
  }
  #ifdef USERPROG
  // free page table
  page_table_destroy(&cur->page_table);
  #endif

  // Unblock the waiting parent process, if any, from wait().
  // now its resource (pcb on page, etc.) can be freed.
  sema_up (&cur->pcb->sema_wait);

  // Destroy the pcb object by itself, if it is orphan.
  // see (part 2) of above.
  if (cur->pcb->orphan == true) palloc_free_page (& cur->pcb);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
       cur->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate (NULL);
    pagedir_destroy (pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto finish;
  process_activate ();

  #ifdef USERPROG
  /* 이제 user thread가 완전히 설정된 상태에서 page table 초기화 */
  page_table_init (&t->page_table);
  
  // init mmap_list
  list_init(&t->mmap_list);
  t->next_mapid = 1;
  #endif

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
  {
    printf ("load: %s: open failed\n", file_name);
    goto finish;
  }
  
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
  {
    printf ("load: %s: error loading executable\n", file_name);
    goto finish;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length (file))
      goto finish;
    file_seek (file, file_ofs);

    if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
      goto finish;
    file_ofs += sizeof phdr;
    switch (phdr.p_type)
    {
    case PT_NULL:
    case PT_NOTE:
    case PT_PHDR:
    case PT_STACK:
    default:
      /* Ignore this segment. */
      break;
    case PT_DYNAMIC:
    case PT_INTERP:
    case PT_SHLIB:
      goto finish;
    case PT_LOAD:
      if (validate_segment (&phdr, file))
      {
        bool writable = (phdr.p_flags & PF_W) != 0;
        uint32_t file_page = phdr.p_offset & ~PGMASK;
        uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
        uint32_t page_offset = phdr.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (phdr.p_filesz > 0)
        {
          /* Normal segment.
             Read initial part from disk and zero the rest. */
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                        - read_bytes);
        }
        else
        {
          /* Entirely zero.
             Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment (file, file_page, (void *) mem_page,
                           read_bytes, zero_bytes, writable))
          goto finish;
      }
      else
        goto finish;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto finish;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  /* Deny writes to executables. */
  file_deny_write (file);
  thread_current()->executing_file = file;

  success = true;

 finish:
  /* We arrive here whether the load is successful or not. */
  if (!success) {
    /* mmap_list 정리 */
    while (!list_empty(&t->mmap_list)) {
      struct list_elem *e = list_pop_front(&t->mmap_list);
      struct mmap_entry *entry = list_entry(e, struct mmap_entry, elem);
      if (entry->file) file_close(entry->file);
      palloc_free_page(entry);
    }
  }
  // do not close file here, postpone until it terminates
  return success;
}

/* load() helpers. */

bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  #ifdef USERPROG
  /* VM: Use lazy loading instead of eager loading */
  struct thread *cur = thread_current ();

  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
          We will read PAGE_READ_BYTES bytes from FILE
          and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* VM: Create a page entry instead of loading immediately */
      struct page *p;
      
      if (page_read_bytes == 0)
      {
        /* Page is entirely zero - create zero page */
        p = page_create (upage, PAGE_ZERO, writable);
      }
      else
      {
        /* Page has file content - create file-backed page */
        p = page_create_file (upage, file, ofs, page_read_bytes, 
                              page_zero_bytes, writable);
      }
      
      if (p == NULL)
        return false;
      
      /* Insert page into current thread's page table */
      if (!page_insert (&cur->page_table, p))
      {
        free (p);
        return false;
      }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;
    }
  return true;
  #else
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
  #endif
}


/*
 * Push arguments into the stack region of user program
 * (specified by esp), according to the calling convention.
 */
static void
push_arguments (const char* cmdline_tokens[], int argc, void **esp)
{
  ASSERT(argc >= 0);

  int i, len = 0;
  void* argv_addr[argc];
  for (i = 0; i < argc; i++) {
    len = strlen(cmdline_tokens[i]) + 1;
    *esp -= len;
    memcpy(*esp, cmdline_tokens[i], len);
    argv_addr[i] = *esp;
  }

  // word align
  *esp = (void*)((unsigned int)(*esp) & 0xfffffffc);

  // last null
  *esp -= 4;
  *((uint32_t*) *esp) = 0;

  // setting **esp with argvs
  for (i = argc - 1; i >= 0; i--) {
    *esp -= 4;
    *((void**) *esp) = argv_addr[i];
  }

  // setting **argv (addr of stack, esp)
  *esp -= 4;
  *((void**) *esp) = (*esp + 4);

  // setting argc
  *esp -= 4;
  *((int*) *esp) = argc;

  // setting ret addr
  *esp -= 4;
  *((int*) *esp) = 0;

}


/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  #ifdef USERPROG
  /* VM: Use lazy loading for stack page */
  struct thread *cur = thread_current ();
  void *stack_page = ((uint8_t *) PHYS_BASE) - PGSIZE;
  
  /* Create a zero-filled page for the stack */
  struct page *p = page_create (stack_page, PAGE_ZERO, true);
  if (p == NULL)
    return false;
  
  /* Insert into page table */
  if (!page_insert (&cur->page_table, p))
  {
    free (p);
    return false;
  }
  
  /* Load the page immediately since we need to set ESP */
  if (!page_load (p))
  {
    page_delete (&cur->page_table, p);
    return false;
  }
  
  *esp = PHYS_BASE;
  return true;
  
  #else
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
  #endif
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool success = (pagedir_get_page (t->pagedir, upage) == NULL
                  && pagedir_set_page (t->pagedir, upage, kpage, writable));

  #ifdef USERPROG
    if (success)
    {
      struct page *p = page_lookup (&t->page_table, upage);
      if (p != NULL)
      {
        page_set_frame (p, kpage);
      }
    }
  #endif
  return success;
}
