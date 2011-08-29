#ifndef __CONF_H__
#define __CONF_H__

/* Make this header file easier to include in C++ code */
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

/* Parse given CONF-style file. May have [section]s, name=value pairs
   (whitespace stripped), and comments starting with ';' (semicolon). Section
   is "" if name=value pair parsed before any section heading. name:value
   pairs are also supported as a concession to Python's ConfigParser.

   For each name=value pair parsed, call handler function with given user
   pointer as well as section, name, and value (data only valid for duration
   of handler call). Handler should return nonzero on success, zero on error.

   Returns 0 on success, line number of first error on parse error (doesn't
   stop on first error), or -1 on file open error.
*/
int conf_parse(const char* filename,
              int (*handler)(void* user, const char* section,
                             const char* name, const char* value),
              void* user);

/* Same as conf_parse(), but takes a FILE* instead of filename. This doesn't
   close the file when it's fconfshed -- the caller must do that. */
int conf_parse_file(FILE* file,
                   int (*handler)(void* user, const char* section,
                                  const char* name, const char* value),
                   void* user);

/* Nonzero to allow multi-line value parsing, in the style of Python's
   ConfigParser. If allowed, conf_parse() will call the handler with the same
   name for each subsequent line parsed. */
#ifndef CONF_ALLOW_MULTILINE
#define CONF_ALLOW_MULTILINE 1
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CONF_H__ */
