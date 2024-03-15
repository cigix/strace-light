#include <syscall.h>
  .text
  .globl  _start
_start:
  mov $SYS_exit, %rax
  mov $0, %rdi
  syscall  
