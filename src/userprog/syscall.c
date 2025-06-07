#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#ifndef ROUND_UP
#define ROUND_UP(X, STEP) (((X) + (STEP) - 1) / (STEP) * (STEP))
#endif
#ifdef USERPROG
#include "vm/page.h"
#include "userprog/pagedir.h"
#endif

#define STDIN 0
#define STDOUT 1
#define STDERR 2

static void syscall_handler (struct intr_frame *);

static void check_user (const uint8_t *uaddr);
static int32_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static int memread_user (void *src, void *des, size_t bytes);
static struct file_desc* find_file_desc(struct thread *, int fd);

static struct mmap_entry* find_mmap_entry(struct thread *t, mapid_t mapid);
static struct mmap_entry* find_mmap_entry_by_addr(struct thread *t, void *addr);
static bool check_address_overlap(struct thread *t, void *addr, size_t length);
static mapid_t get_next_mapid(struct thread *t);

void sys_halt (void);
void sys_exit (int);
pid_t sys_exec (const char *cmdline);
int sys_wait (pid_t pid);

bool sys_create(const char* filename, unsigned initial_size);
bool sys_remove(const char* filename);
int sys_open(const char* file);
int sys_filesize(int fd);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
mapid_t sys_mmap(int fd, void *addr);
void sys_munmap(mapid_t mapping);

struct lock filesys_lock;

void
syscall_init (void)
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// in case of invalid memory access, fail and exit.
static void fail_invalid_access(void) {
  if (lock_held_by_current_thread(&filesys_lock))
    lock_release (&filesys_lock);

  sys_exit (-1);
  NOT_REACHED();
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_number;
  int intsize = 4;
  int ptrsize = 4;
  int fd;
  ASSERT( sizeof(syscall_number) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  memread_user(f->esp, &syscall_number, intsize);


  // Dispatch w.r.t system call number
  // SYS_*** constants are defined in syscall-nr.h
  switch (syscall_number) {
  case SYS_HALT: // 0
    {
      sys_halt();
      NOT_REACHED();
      break;
    }

  case SYS_EXIT: // 1
    {
      int exitcode;
      memread_user(f->esp + 4, &exitcode, intsize);

      sys_exit(exitcode);
      NOT_REACHED();
      break;
    }

  case SYS_EXEC: // 2
    {
      void* cmdline;
	    memread_user(f->esp + 4, &cmdline, ptrsize);

      uint32_t return_code = sys_exec((const char*) cmdline);
      f->eax = return_code;
      break;
    }

  case SYS_WAIT: // 3
    {
      pid_t pid;
  	  memread_user(f->esp + 4, &pid, sizeof(pid));

      uint32_t return_code = sys_wait(pid);
      f->eax = return_code;
      break;
    }

  case SYS_CREATE: // 4
    {
      const char* filename;
      unsigned initial_size;
      bool return_code;
	    int sizek = sizeof(initial_size);
      memread_user(f->esp + 4, &filename, ptrsize);
      memread_user(f->esp + 8, &initial_size, sizek);

      return_code = sys_create(filename, initial_size);
      f->eax = return_code;
      break;
    }

  case SYS_REMOVE: // 5
    {
      const char* filename;
      bool return_code;
      memread_user(f->esp + 4, &filename, ptrsize);

      return_code = sys_remove(filename);
      f->eax = return_code;
      break;
    }

  case SYS_OPEN: // 6
    {
      const char* filename;
      int return_code;
      
      memread_user(f->esp + 4, &filename,ptrsize);

      return_code = sys_open(filename);
      f->eax = return_code;
      break;
    }

  case SYS_FILESIZE: // 7
    {
      int return_code;
      memread_user(f->esp + 4, &fd, intsize);

      return_code = sys_filesize(fd);
      f->eax = return_code;
      break;
    }

  case SYS_READ: // 8
    {
      uint32_t return_code;
      void *buffer;
      unsigned size;
	    int sizek =sizeof(size);
      memread_user(f->esp + 4, &fd, intsize);
      memread_user(f->esp + 8, &buffer, ptrsize);
      memread_user(f->esp + 12, &size, sizek);

      return_code = sys_read(fd, buffer, size);
      f->eax = return_code;
      break;
    }

  case SYS_WRITE: // 9
    {
      uint32_t return_code;
      const void *buffer;
      unsigned size;
	    int sizek2 = sizeof(buffer);
	    int sizek = sizeof(size);
      memread_user(f->esp + 4, &fd, intsize);
      memread_user(f->esp + 8, &buffer, sizek2);
      memread_user(f->esp + 12, &size, sizek);

      return_code = sys_write(fd, buffer, size);
      f->eax = return_code;
      break;
    }

  case SYS_SEEK: // 10
    {
      unsigned position;
	    int sizek = sizeof(position);
      memread_user(f->esp + 4, &fd, intsize);
      memread_user(f->esp + 8, &position, sizek);

      sys_seek(fd, position);
      break;
    }

  case SYS_TELL: // 11
    {
      uint32_t return_code;

      memread_user(f->esp + 4, &fd, intsize);

      return_code = sys_tell(fd);
      f->eax = return_code;
      break;
    }

  case SYS_CLOSE: // 12
    {
      memread_user(f->esp + 4, &fd, intsize);

      sys_close(fd);
      break;
    }
  case SYS_MMAP: // 13
    {
      int fd;
      void *addr;
      mapid_t return_code;
      
      memread_user(f->esp + 4, &fd, intsize);
      memread_user(f->esp + 8, &addr, ptrsize);

      return_code = sys_mmap(fd, addr);
      f->eax = return_code;
      break;
    }

  case SYS_MUNMAP: // 14
    {
      mapid_t mapping;
      
      memread_user(f->esp + 4, &mapping, sizeof(mapid_t));

      sys_munmap(mapping);
      break;
    }

  /* unhandled case */
  default:
    printf("[ERROR!] system call %d is unimplemented!\n", syscall_number);
    // ensure that waiting (parent) process should wake up and terminate.
    sys_exit(-1);
    break;
  }

}

/****************** System Call Implementations ********************/

void sys_halt(void) {
  shutdown_power_off();
}

void sys_exit(int status) {
  struct thread *current = thread_current ();
  printf("%s: exit(%d)\n", current->name, status);

 
  struct process_control_block *pcb = current->pcb;
  if(pcb != NULL) {
    pcb->exited = 1;
    pcb->exitcode = status;
  }

  thread_exit();
}

pid_t sys_exec(const char *cmdline) {
  const uint8_t* cmd = (const uint8_t*) cmdline;
  check_user(cmd);

  lock_acquire (&filesys_lock); // load() uses filesystem
  pid_t pid = process_execute(cmdline);
  lock_release (&filesys_lock);
  return pid;
}

int sys_wait(pid_t pid) {
  return process_wait(pid);
}

bool sys_create(const char* filename, unsigned initial_size) {
  bool return_code;
  const uint8_t* file = (const uint8_t*)filename;
  check_user(file);

  lock_acquire (&filesys_lock);
  return_code = filesys_create(filename, initial_size);
  lock_release (&filesys_lock);
  return return_code;
}

bool sys_remove(const char* filename) {
  bool return_code;
  const uint8_t* file = (const uint8_t*)filename;
  check_user(file);

  lock_acquire (&filesys_lock);
  return_code = filesys_remove(filename);
  lock_release (&filesys_lock);
  return return_code;
}

int sys_open(const char* file) {
  check_user((const uint8_t*) file);

  struct file* file_opened;
  struct file_desc* fd = palloc_get_page(0);
  if (!fd) {
    return -1;
  }

  lock_acquire (&filesys_lock);
  file_opened = filesys_open(file);
  if (!file_opened) {
    palloc_free_page (fd);
    lock_release (&filesys_lock);
    return -1;
  }

  fd->file = file_opened; //file save
  struct thread *current = thread_current();
  struct list* fd_list = &current->file_descriptors;
  struct thread *back;
  bool empty = list_empty(fd_list);
  if ( empty ) fd->id = 3;
  else {
	fd->id = (list_entry(list_back(fd_list),struct file_desc, elem)->id)+1;
	//fd->id = (back->id) + 1;
  }
  list_push_back(fd_list, &(fd->elem));

  lock_release (&filesys_lock);
  return fd->id;
}

int sys_filesize(int fd) {
  struct file_desc* file_d;

  lock_acquire (&filesys_lock);
  file_d = find_file_desc(thread_current(), fd);

  if(file_d == NULL) {
    lock_release (&filesys_lock);
    return -1;
  }

  int ret = file_length(file_d->file);
  lock_release (&filesys_lock);
  return ret;
}

void sys_seek(int fd, unsigned position) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd);

  if(file_d && file_d->file) {
    file_seek(file_d->file, position);
  }
  else
    return;

  lock_release (&filesys_lock);
}

unsigned sys_tell(int fd) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd);

  unsigned ret;
  if(file_d && file_d->file) {
    ret = file_tell(file_d->file);
  }
  else
    ret = -1;

  lock_release (&filesys_lock);
  return ret;
}

void sys_close(int fd) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd);

  if(file_d && file_d->file) {
    file_close(file_d->file);
    list_remove(&(file_d->elem));
    palloc_free_page(file_d);
  }
  lock_release (&filesys_lock);
}

int sys_read(int fd, void *buffer, unsigned size) {
  check_user((const uint8_t*) buffer);
  check_user((const uint8_t*) buffer + size - 1);

  lock_acquire (&filesys_lock);
  int ret;

  if(fd == STDIN) {
    int i;
    for(i = 0; i < size; ++i) {
      if(! put_user(buffer + i, input_getc()) ) {
        lock_release (&filesys_lock);
        sys_exit(-1); // segfault
      }
    }
    ret = size;
  }
  else {
    // read from file
    struct file_desc* file_d = find_file_desc(thread_current(), fd);

    if(file_d && file_d->file) {
      ret = file_read(file_d->file, buffer, size);
    }
    else // no such file or can't open
      ret = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  check_user((const uint8_t*) buffer);
  check_user((const uint8_t*) buffer + size - 1);

  lock_acquire (&filesys_lock);
  int ret;

  if(fd == STDOUT) { // write to stdout
    putbuf(buffer, size);
    ret = size;
  }
  else {
    // write into file
    struct file_desc* file_d = find_file_desc(thread_current(), fd);

    if(file_d && file_d->file) {
      ret = file_write(file_d->file, buffer, size);
    }
    else // no such file or can't open
      ret = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}

mapid_t sys_mmap(int fd, void *addr) {
  struct thread *current = thread_current();
  
  /* 기본 인자 검증 */
  if (addr != NULL) {
    check_user((const uint8_t*) addr);
  }
  
  if (addr == NULL) {
    return MAP_FAILED;
  }
  
  if (((uint32_t) addr) % PGSIZE != 0) {
    return MAP_FAILED;
  }
  
  if (fd < 0 || fd == STDIN || fd == STDOUT) {
    return MAP_FAILED;
  }
  
  /* 파일 디스크립터 확인 및 파일 정보 얻기 */
  lock_acquire (&filesys_lock);
  
  struct file_desc* file_d = find_file_desc(current, fd);
  if (file_d == NULL || file_d->file == NULL) {
    lock_release (&filesys_lock);
    return MAP_FAILED;
  }
  
  /* 파일 크기 확인 */
  off_t file_size = file_length(file_d->file);
  if (file_size <= 0) {
    lock_release (&filesys_lock);
    return MAP_FAILED;
  }
  
  /* 매핑 크기 계산 (페이지 단위로 반올림) */
  size_t mapping_length = ROUND_UP(file_size, PGSIZE);
  
  /* 주소 겹침 검사 */
  if (check_address_overlap(current, addr, mapping_length)) {
    lock_release (&filesys_lock);
    return MAP_FAILED;
  }
  
  /* 파일 재오픈 (독립적인 파일 포인터 필요) */
  struct file *mapped_file = file_reopen(file_d->file);
  if (mapped_file == NULL) {
    lock_release (&filesys_lock);
    return MAP_FAILED;
  }
  
  lock_release (&filesys_lock);
  
  /* mmap_entry 생성 및 초기화 */
  struct mmap_entry *entry = palloc_get_page(0);
  if (entry == NULL) {
    file_close(mapped_file);
    return MAP_FAILED;
  }
  
  entry->mapid = get_next_mapid(current);
  entry->addr = addr;
  entry->length = mapping_length;
  entry->file = mapped_file;
  entry->offset = 0;
  
  /* 프로세스의 mmap_list에 추가 */
  list_push_back(&current->mmap_list, &entry->elem);
  
  // printf("[DEBUG] sys_mmap success: fd=%d, addr=%p, mapid=%d, length=%zu\n", 
  //        fd, addr, entry->mapid, mapping_length);
  
  return entry->mapid;
}

void sys_munmap(mapid_t mapping) {
  struct thread *current = thread_current();
  
  /* Find the mmap entry */
  struct mmap_entry *entry = find_mmap_entry(current, mapping);
  if (entry == NULL) {
    return; /* Invalid mapping ID */
  }
  
  /* Remove from mmap list */
  list_remove(&entry->elem);
  
  /* Unmap all pages in this mapping */
  void *addr = entry->addr;
  size_t length = entry->length;
  
  void *page_addr;
  for (page_addr = addr; 
    (uint8_t*)page_addr < (uint8_t*)addr + length; 
    page_addr = (uint8_t*)page_addr + PGSIZE) {
    struct page *p = page_lookup(&current->page_table, page_addr);
    if (p != NULL){
      /* If page is in memory and dirty, write back to file */
      if (p->state == PAGE_MEMORY && p->frame != NULL){
        if (pagedir_is_dirty(current->pagedir, page_addr)){
          /* Write dirty page back to file */
          lock_acquire (&filesys_lock);
          file_seek(entry->file, p->file_offset);
          file_write(entry->file, p->frame, p->file_bytes);
          lock_release (&filesys_lock);
        }
      }
      
      /* Remove page from page table */
      page_delete(&current->page_table, p);
    }
  }
  
  /* Close the file and free the entry */
  lock_acquire (&filesys_lock);
  file_close(entry->file);
  lock_release (&filesys_lock);
  
  palloc_free_page(entry);
}
/****************** Helper Functions on Memory Access ********************/
static void
check_user (const uint8_t *uaddr) {
  // check uaddr range or segfaults
  int32_t result = get_user(uaddr);
  if( result  == -1)
  	fail_invalid_access();
}

static int32_t
get_user (const uint8_t *uaddr) {
  int result; 
  if (! ((void*)uaddr < PHYS_BASE)) {
      result = -1;
	  return result;
  }

  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

static bool
put_user (uint8_t *udst, uint8_t byte) {
  if (! ((void*)udst < PHYS_BASE)) {
    return 0;
  }

  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  bool result = (error_code != -1);
  return result;
}
static int
memread_user (void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i;
  uint8_t *byte_src = (uint8_t*)src;
  for(i=0; i<bytes; i++) {
    value = get_user(byte_src + i);
    if(value != -1) 
		  *(char*)(dst + i) = value & 0xff;
    else
      fail_invalid_access();
  }
  return (int)bytes;
}

/****** Helper Function on File Access ********************/

static struct file_desc*
find_file_desc(struct thread *t, int fd)
{
  ASSERT (t != NULL);

  if (fd < 3) {
    return NULL;
  }

 
  bool empty = list_empty(&t -> file_descriptors);
  if (!empty) {
    struct list_elem *e;
    for(e = list_begin(&t->file_descriptors); e != list_end(&t->file_descriptors); e = list_next(e)){
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc->id == fd) {
        return desc;
      }
    }
  }

  return NULL;
}

static struct mmap_entry*
find_mmap_entry(struct thread *t, mapid_t mapid)
{
  ASSERT (t != NULL);
  
  if (list_empty(&t->mmap_list)) {
    return NULL;
  }
  
  struct list_elem *e;
  for (e = list_begin(&t->mmap_list); e != list_end(&t->mmap_list); e = list_next(e))
  {
    struct mmap_entry *entry = list_entry(e, struct mmap_entry, elem);
    if (entry->mapid == mapid) {
      return entry;
    }
  }
  
  return NULL;
}

static bool
check_address_overlap(struct thread *t, void *addr, size_t length)
{
  ASSERT (t != NULL);
  
  void *start = addr;
  void *end = (uint8_t*)addr + length;
  
  if (list_empty(&t->mmap_list)) {
    return false; // 겹침 없음
  }
  
  struct list_elem *e;
  for (e = list_begin(&t->mmap_list); e != list_end(&t->mmap_list); e = list_next(e))
  {
    struct mmap_entry *entry = list_entry(e, struct mmap_entry, elem);
    void *entry_start = entry->addr;
    void *entry_end = (uint8_t*)entry->addr + entry->length;
    
    // 겹침 검사: (start < entry_end) && (end > entry_start)
    if (start < entry_end && end > entry_start) {
      return true; // 겹침 발생
    }
  }
  
  return false; // 겹침 없음
}

static mapid_t
get_next_mapid(struct thread *t)
{
  ASSERT (t != NULL);
  return t->next_mapid++;
}

/* Find mmap entry that contains the given address */
static struct mmap_entry*
find_mmap_entry_by_addr(struct thread *t, void *addr)
{
  ASSERT (t != NULL);
  
  if (list_empty(&t->mmap_list)) {
    return NULL;
  }
  
  struct list_elem *e;
  for (e = list_begin(&t->mmap_list); e != list_end(&t->mmap_list); e = list_next(e))
  {
    struct mmap_entry *entry = list_entry(e, struct mmap_entry, elem);
    void *entry_start = entry->addr;
    void *entry_end = (uint8_t*)entry->addr + entry->length;
    
    /* Check if address falls within this mapping range */
    if (addr >= entry_start && addr < entry_end) {
      return entry;
    }
  }
  
  return NULL;
}