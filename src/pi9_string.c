#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <assert.h>

#include "pi9_string.h"

static inline char*
ccopy(const char *str, size_t len)
{
   char *cpy = calloc(1, len + 1);
   return (cpy ? memcpy(cpy, str, len) : NULL);
}

void
pi9_string_release(struct pi9_string *string)
{
   if (!string)
      return;

   if (string->is_heap)
      free(string->data);

   memset(string, 0, sizeof(struct pi9_string));
}

bool
pi9_string_set_cstr_with_length(struct pi9_string *string, const char *data, size_t len, bool is_heap)
{
   assert(string);

   char *copy = (char*)data;
   if (is_heap && data && len > 0 && !(copy = ccopy(data, len)))
      return false;

   pi9_string_release(string);
   string->is_heap = is_heap;
   string->data = (len > 0 ? copy : NULL);
   string->size = len;
   return true;
}

bool
pi9_string_set_cstr(struct pi9_string *string, const char *data, bool is_heap)
{
   assert(string);
   return pi9_string_set_cstr_with_length(string, data, (data ? strlen(data) : 0), is_heap);
}

bool
pi9_string_set_varg(struct pi9_string *string, const char *fmt, va_list args)
{
   va_list cpy;
   va_copy(cpy, args);

   char *str = NULL;
   const size_t len = vsnprintf(NULL, 0, fmt, args);
   if (len > 0 && !(str = malloc(len + 1)))
      return false;

   vsnprintf(str, len + 1, fmt, cpy);

   pi9_string_release(string);
   string->is_heap = true;
   string->data = (len > 0 ? str : NULL);
   string->size = len;
   return true;
}

bool
pi9_string_set_format(struct pi9_string *string, const char *fmt, ...)
{
   va_list argp;
   va_start(argp, fmt);
   const bool ret = pi9_string_set_varg(string, fmt, argp);
   va_end(argp);
   return ret;
}

bool
pi9_string_set(struct pi9_string *string, const struct pi9_string *other, bool is_heap)
{
   if (!is_heap && string->data == other->data) {
      string->size = other->size;
      return true;
   }

   return pi9_string_set_cstr_with_length(string, other->data, other->size, is_heap);
}
