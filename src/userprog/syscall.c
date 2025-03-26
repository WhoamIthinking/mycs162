#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "devices/shutdown.h" // 确保包含头文件
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static bool get_user(const uint8_t *src, uint8_t *dst);
bool validate_string(const char *str);
bool validate_arguments(struct intr_frame *f, int arg_count);
bool validate_buffer(void *addr, unsigned size);
int parse_cmdline(const char *cmd_line, char **argv, int max_args);


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
      if (!validate_arguments(f, 3)) {
        thread_current()->exit_status = -1;
        sys_exit(-1);
      }
      int fd = (int)stack[1];
      const void *buffer = (const void *)stack[2];
      unsigned size = (unsigned)stack[3];
  
      /* 增强型缓冲区验证 */
      if (size > 0 && 
        !validate_buffer((void *)buffer, size)) {
        thread_current()->exit_status = -1;
        sys_exit(-1);
      }
  
      f->eax = sys_write(fd, buffer, size);
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
    case SYS_READ:
      if (!validate_arguments(f, 3)) {  // 检查参数数量
        sys_exit(-1);
      }
      f->eax = sys_read(stack[1], (void *)stack[2], (unsigned)stack[3]);
      break;
    case SYS_CLOSE:
      if (!validate_arguments(f, 1)) {  // 检查参数数量
        sys_exit(-1);
      }
      f->eax = sys_close(stack[1]);
      break;
    case SYS_FILESIZE:
      if (!validate_arguments(f, 1)) {  // 检查参数数量
        sys_exit(-1);
      }
      f->eax = sys_filesize(stack[1]);
      break;
    case SYS_EXEC:
      if (!validate_arguments(f, 1)) {
        thread_current()->exit_status = -1;
        sys_exit(-1);
      }
  
      const char *cmd_line = (const char *)stack[1];
      char kernel_cmd[1024];
  
      /* 严格验证命令行参数 */
      if (!validate_string(cmd_line) || 
          strlen(cmd_line) >= sizeof(kernel_cmd)) {
        thread_current()->exit_status = -1;
        sys_exit(-1);
      }
      f->eax = sys_exec(kernel_cmd);
      break;
    default:
      printf("Unknown system call: %d\n", syscall_num);
      thread_exit();
  }
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

// 新增缓冲区验证辅助函数
bool validate_buffer(void *addr, unsigned size) {
  uint8_t *start = (uint8_t *)addr;
  uint8_t *end = start + size;
  
  // 处理地址环绕的情况
  if (end < start) return false;
  
  for (uint8_t *p = start; p < end; p++) {
    if (!is_user_vaddr(p)) return false;
    
    // 检查物理页存在性
    void *phys_page = pagedir_get_page(thread_current()->pagedir, pg_round_down(p));
    if (!phys_page) return false;
  }
  return true;
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

/* 实现sys_write函数 */
int sys_write(int fd, const void *buffer, unsigned size) {
  struct thread *t = thread_current();
  
  /* 1. 验证文件描述符 */
  if (fd < 0 || fd >= MAX_FILE) return -1;
  
  /* 2. 处理标准输出/错误 */
  if (fd == STDOUT_FILENO) {
      putbuf(buffer, size);
      return size;
  }
  
  /* 3. 验证普通文件描述符 */
  struct file *file = t->file_list[fd];
  if (file == NULL || fd == STDIN_FILENO) return -1;
  
  /* 4. 0字节特殊处理 */
  if (size == 0) return 0;
  
  int bytes_written = file_write_at(file, buffer, size, file_tell(file));
  if (bytes_written > 0)
      file_seek(file, file_tell(file) + bytes_written);
  return bytes_written;
}



bool sys_create(const char *name, unsigned initial_size){
  if(validate_string(name)==false){
    sys_exit(-1);
    return false;
  }
  return filesys_create(name, initial_size);
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
  if(fd>=MAX_FILE){
    file_close(file);
    return -1;
  }
  thread_current()->next_fd++;
  thread_current()->file_list[fd] = file;
  return fd;
}

int sys_close(int fd){
  /* 严格验证文件描述符范围：
     * 1. 必须 >= 0（基础类型检查）
     * 2. 不能是标准输入输出（0/1）
     * 3. 不能超过最大文件描述符限制 */
  if(fd<2||fd>=thread_current()->next_fd){
    return -1;
  }
  struct file *file = thread_current()->file_list[fd];
  if(file==NULL){
    return -1;
  }
  thread_current()->file_list[fd] = NULL;
  file_close(file);
  return 0;
}

// 实现sys_read函数（需要与文件系统配合）
int sys_read(int fd, void *buffer, unsigned size) {
  struct thread *t = thread_current();
  
  /* 1. 验证文件描述符 */
  if (fd < 0 || fd >= MAX_FILE || 
      (fd == STDOUT_FILENO ) ||  // 不能读stdout
      t->file_list[fd] == NULL) {
      return -1;
  }

  /* 2. 处理特殊0字节读请求 */
  if (size == 0) {
      return 0;
  }

  if(fd==STDIN_FILENO){
    uint8_t *buf = (uint8_t *)buffer;
    for(unsigned i=0;i<size;i++){
      buf[i]=input_getc();
    }
    return size;
  }
  /* 3. 验证缓冲区有效性（需要逐页检查） */
  if (!validate_buffer(buffer, size)) {  // true表示需要可写权限
      sys_exit(-1);
  }

  /* 3. 执行读取操作 */
  struct file *file = t->file_list[fd];
  off_t offset = file_tell(file);
  
  lock_acquire(&t->file_lock);
  int bytes_read = file_read_at(file, buffer, size, offset);
  if (bytes_read > 0)
      file_seek(file, offset + bytes_read);
  lock_release(&t->file_lock);

  return bytes_read;
}

int sys_filesize(int fd) {
  struct thread *t = thread_current();
  
  /* 验证文件描述符有效性 */
  if (fd < 0 || fd >= MAX_FILE || 
      t->file_list[fd] == NULL) {
      return -1;
  }
  
  /* 获取文件长度 */
  lock_acquire(&thread_current()->file_lock);
  int size = file_length(t->file_list[fd]);
  lock_release(&thread_current()->file_lock);
  
  return size;
}

/* 实现sys_exec函数 */
int sys_exec(const char *cmd_line) {
  /* 参数解析 */
  char *argv[64];
  int argc = parse_cmdline(cmd_line, argv, 64);
  if (argc == 0) return -1;

  /* 尝试加载可执行文件 */
  struct file *file = filesys_open(argv[0]);
  if (!file) return -1;
  
  /* 创建子进程 */
  tid_t pid = process_execute(cmd_line);
  if (pid == TID_ERROR) return -1;
  file_close(file);
  
  return pid;
}

/* 命令行参数解析函数 */
int parse_cmdline(const char *cmd_line, char **argv, int max_args) {
  int argc = 0;
  bool in_arg = false;

  // Create a writable copy of cmd_line
  char cmd_copy[1024];
  strlcpy(cmd_copy, cmd_line, sizeof(cmd_copy));
  
  for (char *p = cmd_copy; *p && argc < max_args; p++) {
      if (*p == ' ' && in_arg) {
          in_arg = false;
          *p = '\0';
      } else if (*p != ' ' && !in_arg) {
          argv[argc++] = p;
          in_arg = true;
      }
  }
  return argc;
}