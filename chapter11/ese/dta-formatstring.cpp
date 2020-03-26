/*
 * Simple DTA tool that detects format string vulnerabilities.
 *
 * See /usr/include/i386-linux-gnu/asm/unistd_32.h for x86 (32 bit) syscall numbers.
 * See /usr/include/asm-generic/unistd.h for x64 syscall numbers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#include <map>
#include <string>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/net.h>

#include "pin.H"

#include "branch_pred.h"
#include "libdft_api.h"
#include "syscall_desc.h"
#include "tagmap.h"

/* ins descriptors */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

static std::map<int, uint8_t> fd2color;
static std::map<uint8_t, std::string> color2fname;

#define MAX_COLOR 0x80
#define DBG_PRINTS 1

void alert(uintptr_t addr, uint8_t tag)
{
  fprintf(stderr, "\n(dta-formatstring) !!!!!!! ADDRESS 0x%x IS TAINTED (tag=0x%02x), ABORTING !!!!!!!\n",
          addr, tag);

  for (unsigned c = 0x01; c <= MAX_COLOR; c <<= 1)
  {
    if (tag & c)
    {
      fprintf(stderr, "  tainted by color = 0x%02x (%s)\n", c, color2fname[c].c_str());
    }
  }
  exit(1);
}

/* ------- TAINT SOURCES ------- */

uint8_t next_color = 0x01;

//maps each opened file with a color.
static void
post_open_hook(syscall_ctx_t *ctx)
{
  uint8_t color;
  int fd            =         (int)ctx->ret;
  const char *fname = (const char*)ctx->arg[SYSCALL_ARG0];

  if(unlikely((int)ctx->ret < 0)) {
    return;
  }

  if(strstr(fname, ".so") || strstr(fname, ".so.")) {
    return;
  }

#if DBG_PRINTS
  fprintf(stderr, "(dta-formatstring) opening %s at fd %u with color 0x%02x\n", fname, fd, next_color);
#endif

  if(!fd2color[fd]) {
    color = next_color;
    fd2color[fd] = color;
    if(next_color < MAX_COLOR) next_color <<= 1;
  } else {
    /* reuse color of file with same fd which was opened previously */
    color = fd2color[fd];
  }

  /* multiple files may get the same color if the same fd is reused
   * or we run out of colors */
  if(color2fname[color].empty()) color2fname[color] = std::string(fname);
  else color2fname[color] += " | " + std::string(fname);
}

//taints byte received from the network
static void
post_socketcall_hook(syscall_ctx_t *ctx)
{
  int fd;
  void *buf;
  size_t len;
  uint8_t color;

  int call            =            (int)ctx->arg[SYSCALL_ARG0];
  unsigned long *args = (unsigned long*)ctx->arg[SYSCALL_ARG1];

  switch(call) {
  case SYS_RECV:
  case SYS_RECVFROM:
    if(unlikely(ctx->ret <= 0)) {
      return;
    }

    fd  =    (int)args[0];
    buf =  (void*)args[1];
    len = (size_t)ctx->ret;

    if(!fd2color[fd]) {
      color = next_color;
      fd2color[fd] = color;
      if(next_color < MAX_COLOR) next_color <<= 1;
    } else {
      /* reuse color of file with same fd which was opened previously */
      color = fd2color[fd];
    }

#if DBG_PRINTS
    fprintf(stderr, "(dta-formatstring) recv: %zu bytes from fd %u\n", len, fd);

    for(size_t i = 0; i < len; i++) {
      if(isprint(((char*)buf)[i])) fprintf(stderr, "%c", ((char*)buf)[i]);
      else                         fprintf(stderr, "\\x%02x", ((char*)buf)[i]);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "(dta-formatstring) tainting bytes %p -- 0x%x with tag 0x%x\n", 
            buf, (uintptr_t)buf+len, 0x01);
#endif

    tagmap_setn((uintptr_t)buf, len, color);

    break;

  default:
    break;
  }
}

static void
post_read_hook(syscall_ctx_t *ctx)
{
  int fd     =    (int)ctx->arg[SYSCALL_ARG0];
  void *buf  =  (void*)ctx->arg[SYSCALL_ARG1];
  size_t len = (size_t)ctx->ret;
  uint8_t color;

  if(unlikely(len <= 0)) {
    return;
  }

#if DBG_PRINTS
  fprintf(stderr, "(dta-formatstring) read: %zu bytes from fd %u\n", len, fd);
#endif

  color = fd2color[fd];
  if(color) {
#if DBG_PRINTS
    fprintf(stderr, "(dta-formatstring) tainting bytes %p -- 0x%x with color 0x%x\n", 
            buf, (uintptr_t)buf+len, color);
#endif
    tagmap_setn((uintptr_t)buf, len, color);
  } else {
#if DBG_PRINTS
    fprintf(stderr, "(dta-formatstring) clearing taint on bytes %p -- 0x%x\n",
            buf, (uintptr_t)buf+len);
#endif
    tagmap_clrn((uintptr_t)buf, len);
  }
}

/* ------- TAINT SINKS ------- */

//check if the format string of the called function is tainted.
void check_tainted_string_fmt(ADDRINT arg)
{
  char * format_string = (char *)arg;
  uint8_t tag;

  for(char * it = format_string; *it != '\0'; it++) {
    tag = tagmap_getb((uintptr_t)it);
    if(tag != 0) alert((uintptr_t)it, tag);
  }
}

static void
dta_instrument_call(INS ins)
{
  // if (likely(INS_IsDirectBranchOrCall(ins))) <-- for performance. TODO check the usage of likely keyword
  if (INS_IsDirectBranchOrCall(ins))
  {
    int arg_num = 0;
    std::string func = RTN_FindNameByAddress(INS_DirectBranchOrCallTargetAddress(ins));

    if (func.find("printf") != string::npos)
    {
      if(func.compare("printf") == 0 || func.compare("vprintf") == 0)
      {
        arg_num = 0;
      } 
      else if(func.compare("fprintf") == 0 || func.compare("dprintf") == 0 ||
              func.compare("sprintf") == 0 || func.compare("vfprintf") == 0 ||
              func.compare("vdprintf") == 0 || func.compare("vsprintf") == 0)
      {
        arg_num = 1;
      }
      else if(func.compare("snprintf") == 0 || func.compare("vsnprintf") == 0)
      {
        arg_num = 2;
      }

      INS_InsertCall(ins,
        IPOINT_BEFORE,
        (AFUNPTR)check_tainted_string_fmt,
        IARG_FUNCARG_CALLSITE_VALUE, arg_num,
        IARG_END);
    }
  }
}

/* --------- MAIN ---------------*/

int main(int argc, char **argv)
{
  PIN_InitSymbols();

  if (unlikely(PIN_Init(argc, argv)))
  {
    return 1;
  }

  if (unlikely(libdft_init() != 0))
  {
    libdft_die();
    return 1;
  }

  syscall_set_post(&syscall_desc[__NR_open], post_open_hook);
  syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
  syscall_set_post(&syscall_desc[__NR_socketcall], post_socketcall_hook);

  /* instrument call */
  (void)ins_set_pre(&ins_desc[XED_ICLASS_CALL_NEAR],
                    dta_instrument_call);

  PIN_StartProgram();

  return 0;
}
