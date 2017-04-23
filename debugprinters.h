#ifndef __DEBUGPRINTERS_H__
#define __DEBUGPRINTERS_H__

#include "sm_io_wrap.h"

#define DEBUG 1

#ifdef  DEBUG
#define debug_puts(s) puts(s)
#define debug_print_int(s,n)  print_int(s,n)
// #define debug_print_hex(s,n)  print_hex(s,n)
#else 
#define debug_puts(s) void
#define debug_print_int(s,n) void
#endif

void print_int(const char* fmt, int n);

void print_void(const char* fmt, void* n);

#endif
