#ifndef __pi9_string_h__
#define __pi9_string_h__

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

struct pi9_string {
   char *data;
   uint16_t size;
   bool is_heap;
};

static inline bool
pi9_string_eq(const struct pi9_string *a, const struct pi9_string *b)
{
   return (a->data == b->data) || (a->size == b->size && !memcmp(a->data, b->data, a->size));
}

static inline bool
pi9_string_eq_cstr(const struct pi9_string *a, const char *cstr)
{
   return (cstr == a->data) || (a->data && cstr && !strcmp(a->data, cstr));
}

static inline bool
pi9_cstreq(const char *a, const char *b)
{
   return (a == b) || (a && b && !strcmp(a, b));
}

static inline bool
pi9_cstrneq(const char *a, const char *b, size_t len)
{
   return (a == b) || (a && b && !strncmp(a, b, len));
}


void pi9_string_release(struct pi9_string *string);
bool pi9_string_set_cstr(struct pi9_string *string, const char *data, bool is_heap);
bool pi9_string_set_cstr_with_length(struct pi9_string *string, const char *data, uint16_t length, bool is_heap);
bool pi9_string_set(struct pi9_string *string, const struct pi9_string *other, bool is_heap);

#endif /* __pi9_string_h__ */
