#include <stdlib.h>
#include <stddef.h>
#include <assert.h>

#include "pi9_string.h"

static inline char*
ccopy(const char *str, size_t len)
{
   char *cpy = calloc(1, len);
   return (cpy ? memcpy(cpy, str, len) : NULL);
}

void
pi9_string_release(struct pi9_string *string)
{
   assert(string);

   if (string->is_heap && string->data)
      free(string->data);

   string->data = NULL;
   string->size = 0;
}

bool
pi9_string_set_cstr_with_length(struct pi9_string *string, const char *data, uint16_t length, bool is_heap)
{
   assert(string);

   char *copy = (char*)data;
   if (is_heap && data && length > 0 && !(copy = ccopy(data, length)))
      return false;

   pi9_string_release(string);
   string->is_heap = is_heap;
   string->data = (length > 0 ? copy : NULL);
   string->size = length;
   return true;
}

bool
pi9_string_set_cstr(struct pi9_string *string, const char *data, bool is_heap)
{
   assert(string);
   return pi9_string_set_cstr_with_length(string, data, (data ? strlen(data) : 0), is_heap);
}

bool
pi9_string_set(struct pi9_string *string, const struct pi9_string *other, bool is_heap)
{
   if (string->data == other->data) {
      string->size = other->size;
      return true;
   }

   return pi9_string_set_cstr_with_length(string, other->data, other->size, is_heap);
}
