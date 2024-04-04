#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <linux/ptrace.h>

#include "syscalls.h"

#define ERROR(key) \
  do { \
    perror(key); \
    exit(1); \
  } while (0)

#define P(request, addr, data) \
  if (ptrace(request, child, addr, data) == -1) \
    ERROR("ptrace(" #request ")")

void *read_ptr(pid_t child, void *addr)
{
#define LONGS_IN_PTR (sizeof(void *) / sizeof(long))
  long data[LONGS_IN_PTR];
  long *a = addr;
  for (size_t i = 0; i < LONGS_IN_PTR; ++i)
  {
    errno = 0;
    data[i] = ptrace(PTRACE_PEEKDATA, child, a + i, NULL);
    if (errno != 0)
      ERROR("ptrace(PTRACE_PEEKDATA)");
  }
  void *ret;
  memcpy(&ret, data, sizeof(void *));
  return ret;
}

char *read_str(pid_t child, void *addr)
{
  size_t len = 0;
  size_t capacity = 1024;
  char *data = malloc(capacity);
  char *a = addr;
  do
  {
    errno = 0;
    long l = ptrace(PTRACE_PEEKDATA, child, a + len, NULL);
    if (errno != 0)
    {
      free(data);
      ERROR("ptrace(PTRACE_PEEKDATA)");
    }

    memcpy(data + len, &l, sizeof(long));
    if (memchr(data + len, 0, sizeof(long)))
      return data;

    len += sizeof(long);
    if (len + sizeof(long) > capacity)
    {
      capacity *= 2;
      data = realloc(data, capacity);
    }
  } while (1);
}

int print(enum TYPE type, uint64_t value, pid_t child)
{
  // This switch need to be kept in line with list_syscalls' syscalls.h' enum
  // TYPE and the usage of it in syscalls.c.
  switch (type)
  {
    case VOID:     return printf("?");
    case ELLIPSIS: return printf("...");
    case INT:      return printf("%d", (int)value);
    case UINT:     return printf("%u", (unsigned)value);
    case LONG:     return printf("%ld", (long)value);
    case UINT32:   return printf("%u", (uint32_t)value);
    case UINT64:   return printf("%lu", (uint64_t)value);
    case SIZE_T:   return printf("%zu", (size_t)value);
    case SSIZE_T:  return printf("%zd", (size_t)value);

    case CHAR_P:
      if (value == 0)
        return printf("NULL");
      char *str = read_str(child, (char *)value);
      int ret = printf("\"%s\"", str);
      free(str);
      return ret;
    case ARGV:
      if (value == 0)
        return printf("NULL");
      char **argv = (char **)value;
      int printed = printf("[");
      for (int i = 0; ; ++i)
      {
        char *arg = read_ptr(child, argv + i);
        if (!arg)
          break;
        if (i)
          printed += printf(", ");
        char *str = read_str(child, arg);
        printed += printf("\"%s\"", str);
        free(str);
      }
      printed += printf("]");
      return printed;
    case ENVP:
      if (value == 0)
        return printf("NULL");
      char **envp = (char **)value;
      int i;
      for (i = 0; ; ++i)
      {
        void *p = read_ptr(child, envp + i);
        if (!p)
          break;
      }
      return printf("%p /* %d vars */", (void *)value, i);

    case VOID_P:
    case UNKNOWN_P:
    case INT_P:
    case UINT_P:
    case UINT32_P:
    case UINT64_P:
    case SIZE_T_P:
    case CHAR_PP:
    case VOID_PP:
      if (value == 0)
        return printf("NULL");
      return printf("%p", (void *)value);

    case UNKNOWN:
      return printf("%#lx", value);
    default:
      fprintf(stderr,
          "Unknown type descriptor: %d. Code needs to be updated.", type);
      exit(1);
  }
}

int main(int argc, char **argv)
{
  pid_t child;
  int status;
  struct ptrace_syscall_info info = {0};

  if (argc < 2)
    return 1;

  child = fork();
  if (child == -1)
    ERROR("fork");
  if (child == 0)
  {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
      ERROR("ptrace(PTRACE_TRACEME)");
    raise(SIGSTOP);
    execvp(argv[1], argv + 1);
    ERROR("execvp");
  }

  while (1)
  {
    if (waitpid(child, &status, 0) == -1)
    {
      perror("waitpid");
      return 1;
    }
    if (WIFSTOPPED(status))
      break;
  }

  //P(PTRACE_ATTACH, NULL, NULL);
  P(PTRACE_SETOPTIONS, NULL, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);

  int nr = 0, i;
  while (1)
  {
    P(PTRACE_SYSCALL, NULL, NULL);
    while (1)
    {
      if (waitpid(child, &status, 0) == -1)
      {
        perror("waitpid");
        return 1;
      }
      if (WIFEXITED(status))
      {
        if (nr)
          printf(" = ?\n");
        int ret = WEXITSTATUS(status);
        printf("+++ exited with %d +++\n", ret);
        return ret;
      }
      if (WIFSTOPPED(status))
        break;
    }
    if (WSTOPSIG(status) == (SIGTRAP|0x80))
    {
      P(PTRACE_GET_SYSCALL_INFO, sizeof(info), &info);
      if (info.op == PTRACE_SYSCALL_INFO_ENTRY)
      {
        for (i = 0; syscalls[i].nr != -1; ++i)
        {
          if (info.entry.nr == (uint64_t)syscalls[i].nr)
            break;
        }
        int printed;
        if (syscalls[i].nr != -1)
          printed = printf("%s(", syscalls[i].name);
        else
          printed = printf("syscall_%#llx(", info.entry.nr);
        for (int j = 0; j < syscalls[i].argc; ++j)
        {
          if (j != 0)
            printed += printf(", ");
          printed += print(syscalls[i].args[j], info.entry.args[j], child);
        }
        printed += printf(")");
        for (; printed < 39; ++printed)
          printf(" ");

        nr = info.entry.nr;
      }
      if (info.op == PTRACE_SYSCALL_INFO_EXIT && nr)
      {
        printf(" = ");
        if (info.exit.is_error)
        {
          int errnum = -info.exit.rval;
          printf("-1 %s (%s)", strerrorname_np(errnum), strerror(errnum));
        }
        else
          print(syscalls[i].retval, info.exit.rval, child);
        printf("\n");
        nr = 0;
      }
    }
  }
}
