#include "userprog/process.h"
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
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp,char **argv, int argc);
 

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Parse the file name and arguments */
  char *save_ptr;
  char *token;
  int argc=0;
  char* argv[128];
  token=strtok_r(fn_copy," ",&save_ptr);
  while(token!=NULL&&argc<128){
    argv[argc]=token;
    argc++;
    token=strtok_r(NULL," ",&save_ptr);
  }
  if(argc==0){
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  struct process_args *args = palloc_get_page(0);
  if (args == NULL){
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  args->program_name = argv[0];
  args->argc = argc;
  args->argv = argv;
  args->fncopy = fn_copy;

  struct thread *cur = thread_current();
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (args->program_name, PRI_DEFAULT, start_process, args);
  struct thread *t = thread_find(tid);

  struct child_process *cp = palloc_get_page(0);
  if (cp == NULL){
    PANIC("failed to allocate memory for child process\n");
  }
  cp->tid = t->tid;
  cp->exit_status = -1;
  cp->exited = false;
  //printf("#########process_execute: Child TID: %d\n", cp->tid);  // 调试输出
  sema_init(&cp->exit_sema, 0);

   // Add to the parent's child list
  lock_acquire(&cur->child_lock);
  list_push_back(&cur->child_list, &cp->elem);
  lock_release(&cur->child_lock);
  t->parent = thread_current();
  if (tid == TID_ERROR){
    palloc_free_page(fn_copy);
  } 
  return tid;
}


/** A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  struct process_args *args = file_name_;
  struct intr_frame if_;
  bool success;

  //printf("start_process: Program name: %s\n", args->program_name);  // 调试输出
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (args->program_name, &if_.eip, &if_.esp,args->argv,args->argc);
  /* If load failed, quit. */
  if (!success){
    palloc_free_page(args->fncopy);
    palloc_free_page(args);
    thread_exit ();
  }
  struct thread *cur = thread_current();
  struct thread *parent = cur->parent;
  //printf("#########start_process: Parent TID: %d\n", parent->tid);  // 调试输出
  //printf("#########parent_name: %s\n", parent->name);  // 调试输出

 
  cur->is_user_process = true;

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid ) 
{ 
  struct thread *cur = thread_current();
  struct list_elem *e;
  //lock_acquire(&cur->child_lock);
  //printf("process_wait: Parent child_list size: %d\n", list_size(&cur->child_list));  // 调试输出
  for(e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e = list_next(e)){
    struct child_process *cp = list_entry(e, struct child_process, elem);
    //printf("process_wait: Checking child TID: %d\n", cp->tid);  // 调试输出
    //printf("the child tid is %d\n", child_tid);
    if(cp->tid == child_tid){
      if(cp->exited){// If the child has already exited
        int status = cp->exit_status;
        list_remove(e);// Remove from the child list
        palloc_free_page(cp);
        return status;
      }else{
        sema_down(&cp->exit_sema);// Wait for the child to exit
        int status = cp->exit_status;
        list_remove(e);
        palloc_free_page(cp);
        return status;
      }
    }
  }
  //lock_release(&cur->child_lock);
  return -1;// If the child is not found
}

/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  if(cur->is_user_process){
    printf("%s: exit(%d)\n",cur->name,cur->exit_status);
  }// Print the exit status
  if(cur->is_user_process&&cur->parent!=NULL){
    struct list *child_list = &cur->parent->child_list;
    
    lock_acquire(&cur->parent->child_lock);
    struct list_elem *e;
    for (e = list_begin (child_list); e != list_end (child_list); e = list_next (e))
    {
      // Find the child process
      struct child_process *cp = list_entry (e, struct child_process, elem);
      //printf("process_exit: Checking child TID: %d\n", cp->tid);  // 调试输出
      if (cp->tid == cur->tid)
      {
        cp->exited = true;
        cp->exit_status = cur->exit_status;
        sema_up(&cp->exit_sema);
        break;
      }
    }
    lock_release(&cur->parent->child_lock);
  }

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

/** Sets up the CPU for running user code in the current
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

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
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

/** Program header.  See [ELF1] 2-2 to 2-4.
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

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp,char **argv, int argc);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);


/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp,char **argv, int argc) 
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
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
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
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
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
          goto done;
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
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp,argv,argc))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  //printf("Loading user program: %s (eip=0x%08x, esp=0x%08x)\n", file_name, eip, esp);


 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/** load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/** Checks whether PHDR describes a valid, loadable segment in
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

/** Loads a segment starting at offset OFS in FILE at address
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
}


/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
   static bool
   setup_stack (void **esp, char **argv, int argc) 
   {
     uint8_t *kpage;
     bool success = false;
     char **args_ptrs;  // 存储参数字符串地址的数组
     int i;
     size_t args_len = 0;
   
     // 计算所有参数字符串的总长度（包含终止符）
     for (i = 0; i < argc; i++) {
       args_len += strlen(argv[i]) + 1;
     }
   
     // 分配用户栈页面
     kpage = palloc_get_page (PAL_USER | PAL_ZERO);
     if (kpage == NULL) 
       return false;
   
     // 将页面安装到用户虚拟地址空间顶部（PHYS_BASE - PGSIZE）
     success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
     if (!success) {
       palloc_free_page (kpage);
       return false;
     }
   
     // 初始化栈指针到页面顶部（PHYS_BASE）
     *esp = (void *) PHYS_BASE;
   
     // 压入参数字符串（从右到左）
     args_ptrs = (char **) palloc_get_page (0); // 临时存储参数字符串地址
     if (args_ptrs == NULL) {
       palloc_free_page (kpage);
       return false;
     }
   
     // 从最后一个参数开始压栈，并记录地址
     for (i = argc - 1; i >= 0; i--) {
       int len = strlen(argv[i]) + 1; // 包含 '\0'
       *esp -= len;
       //printf("len is %d\n", len);
       //printf("copying %s to %p\n", argv[i], *esp);
       memcpy(*esp, argv[i], len);    // 将参数字符串复制到栈中
       args_ptrs[i] = (char *) *esp;  // 记录字符串地址
       //printf("args_ptrs[%d] = %p\n", i, args_ptrs[i]);
       //printf("args_ptrs[%d] = %s\n", i, args_ptrs[i]);
     }
   
     // 在压入哨兵 NULL 前对齐到 4 字节边界
      uintptr_t esp_addr = (uintptr_t)*esp;
      esp_addr -= esp_addr % 4;  // 对齐到最近的4字节边界
      *esp = (void *)esp_addr;
     // 压入哨兵 NULL（argv[argc] = NULL）
      *esp -= sizeof(char *);
      *(char **)*esp = NULL;
   
     // 压入 argv[] 数组（从右到左）
     for (i = argc - 1; i >= 0; i--) {
       *esp -= sizeof(char *);
       *(char **) *esp = args_ptrs[i];
       //printf("pushing %s \n", args_ptrs[i]);
      }
      
     // 压入 argv 的地址（即 argv[0] 的地址）
     char **argv_ptr = (char **) *esp;
     *esp -= sizeof(char **);
     *(char ***) *esp = argv_ptr;
   
     // 压入 argc
     *esp -= sizeof(int);
     *(int *) *esp = argc;
   
     // 压入伪造的返回地址（0）
     *esp -= sizeof(void *);
     *(void **) *esp = 0;
     palloc_free_page (args_ptrs); // 释放临时存储
     return true;
   }

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
