#include "ndff_util.h"
#include <stdarg.h>
#include <syslog.h>

void ndff_log(int priority, char *format, ...)
{
    va_list arg;
    va_start(arg, format);
    vsyslog(priority, format, arg);
    va_end(arg);
}
