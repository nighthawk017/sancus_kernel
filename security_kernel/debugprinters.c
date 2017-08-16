#include "debugprinters.h"

void print_int(const char* fmt,int n) {
	printf(fmt, n);
}

void print_void(const char* fmt,void* n) {
	printf(fmt, n);
}

void print_string(const char* fmt,char* n) {
	printf(fmt, n);
}
