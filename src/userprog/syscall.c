#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "devices/shutdown.h" // 确保包含头文件

static void syscall_handler (struct intr_frame *);
static bool get_user(const uint8_t *src, uint8_t *dst);
bool validate_string(const char *str);
bool validate_arguments(struct intr_frame *f, int arg_count);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* 从用户地址 src 安全读取一个字节到 *dst */
static bool get_user(const uint8_t *src, uint8_t *dst) {
  // 检查地址是否在用户空间且有效
  if (!is_user_vaddr(src) || pagedir_get_page(thread_current()->pagedir, src) == NULL) {
      return false;
  }
  // 通过临时变量访问，避免直接解引用用户指针
  int value;
  asm volatile("movl %1, %%eax; movb (%%eax), %%al; movl %%eax, %0"
               : "=m"(value) : "r"(src) : "eax");
  *dst = (uint8_t)value;
  return true;
}



static void
syscall_handler (struct intr_frame *f) 
{ 
  if (!is_user_vaddr(f->esp) || 
        pagedir_get_page(thread_current()->pagedir, f->esp) == NULL) {
        thread_current()->exit_status = -1;
        sys_exit(-1);
  }
  int *stack = (int*)f->esp;
 
  // 逐字节读取并验证地址
  for (int i = 0; i < sizeof(uint32_t); i++) {
    if (!is_user_vaddr(stack + i) || 
        pagedir_get_page(thread_current()->pagedir,stack + i) == NULL) {
        thread_current()->exit_status = -1;
        sys_exit(-1);
    }
  }
  int syscall_num = stack[0];
  switch(syscall_num){
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_EXIT:
      sys_exit(stack[1]);
      break;
    case SYS_WRITE:
      sys_write(f);
      break;
    case SYS_CREATE:
      if (!validate_arguments(f, 2)) {  // 检查参数数量
        sys_exit(-1);
      }
      f->eax = sys_create((const char *)stack[1], (unsigned)stack[2]);
      break;
    case SYS_OPEN:
      if (!validate_arguments(f, 1)) {  // 检查参数数量
        sys_exit(-1);
      }
      f->eax = sys_open((const char *)stack[1]);
      break;
    default:
      printf("Unknown system call: %d\n", syscall_num);
      thread_exit();
  }
}


void sys_halt(void){
  printf("Shutting down...\n");
  shutdown_power_off();
}

void sys_exit(int status){
  struct thread *cur = thread_current();
  cur->exit_status = status;
  thread_exit();
}

void sys_write(struct intr_frame *f){
  int fd;
  const char *buf;
  size_t size;

  // 从栈中取出参数
  uint32_t *esp=f->esp;
  // 直接读取内核栈上的参数
  fd = esp[1];         // f->esp + 4
  buf = (const char *)esp[2];  // f->esp + 8
  size = esp[3];    // f->esp + 12
  //仅仅处理标准输出
  if(fd!=1){
    printf("fd is not 1\n");
    f->eax=-1;
    return;
  }
  //检查buf是否合法
  if(buf==NULL||!is_user_vaddr(buf)||!is_user_vaddr(buf+size)){
    if(!is_user_vaddr(buf)){
      printf("buf is not in user space\n");
    }
    else if(!is_user_vaddr(buf+size)){
      printf("buf+size is not in user space\n");
    }
    else{
      printf("buf is NULL\n");
    }
    f->eax=-1;
    return;
  }
  //检查buf是否在用户内存空间
  void *page_start = pg_round_down(buf);
  void *page_end = pg_round_down(buf + size - 1);
  for(void *page = page_start; page <= page_end; page += PGSIZE){
    if(pagedir_get_page(thread_current()->pagedir, page) == NULL){
      f->eax = -1;
      return;
    }
  }
  // 写入数据
  char *k_buf = palloc_get_page(0);
  if (k_buf == NULL) {
    f->eax = -1;
    return;
  }
  for(size_t i = 0; i < size; i++){
    uint8_t byte;
    if(!get_user((uint32_t *)(buf + i), &byte)){
      f->eax = -1;
      palloc_free_page(k_buf);
      return;
    }
    k_buf[i] = byte;
  }
  //printf("sys_write: fd=%d, buf=%p, size=%d\n", fd, buf, size);
  putbuf(k_buf, size);
  palloc_free_page(k_buf);
  f->eax = size;
}

bool sys_create(const char *name, unsigned initial_size){
  if(validate_string(name)==false){
    sys_exit(-1);
    return false;
  }
  return filesys_create(name, initial_size);
}


bool validate_arguments(struct intr_frame *f, int arg_count) {
  uint32_t *args = (uint32_t *)f->esp;
  for (int i = 0; i <= arg_count; i++) {  // 包括系统调用号
      if (!is_user_vaddr(&args[i]) || 
          pagedir_get_page(thread_current()->pagedir, &args[i]) == NULL) {
          return false;
      }
  }
  return true;
}

// userprog/syscall.c → validate_string()
bool validate_string(const char *str) {
  if (str == NULL) {
      return false;  // 空指针直接拒绝
  }
  for (const char *p = str; ; p++) {
      if (!is_user_vaddr(p) || 
          pagedir_get_page(thread_current()->pagedir, p) == NULL) {
          return false;  // 地址无效或未映射
      }
      if (*p == '\0') {
          return true;   // 合法字符串以 '\0' 结尾
      }
  }
}

int sys_open(const char *name){
  if(validate_string(name)==false){
    sys_exit(-1);
    return -1;
  }
  struct file *file = filesys_open(name);
  if(file==NULL){
    return -1;
  }
  int fd = thread_current()->next_fd;
  thread_current()->next_fd++;
  thread_current()->file_list[fd] = file;
  return fd;
}
