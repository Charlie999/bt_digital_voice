#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>

static char* logname = "pppoe-server-logger";

#define LOG_INFO "info"
#define LOG_ERR "err"
#define LOG_WARNING "warn"
#define LOG_DEBUG "debug"

#define LOG_PID 0

static void syslog (const char* level, const char *format, ...) {
 va_list args;
 va_start (args, format);
 fprintf(stderr, "[pppoe-server] [%s] ",level);
 vfprintf(stderr,format, args);
 fprintf(stderr, "\n");
 va_end(args);
}

//#define syslog(L, F, ...) __syslog(L, F, __VA_ARGS__)
#define openlog(A,B,C) logname=A
#define closelog() //

#endif
