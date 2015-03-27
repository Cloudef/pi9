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

#define PSTRE(x) (x ? x : "")

static inline bool
pi9_cstr_is_empty(const char *data)
{
   return (!data || *data == 0);
}

static inline bool
pi9_cstr_ends_with(const char *a, const char *b)
{
   const size_t lena = (a ? strlen(a) : 0), lenb = (b ? strlen(b) : 0);
   return (lena >= lenb && !memcmp(a + lena - lenb, PSTRE(b), lenb));
}

static inline bool
pi9_cstr_starts_with(const char *a, const char *b)
{
   const size_t lena = (a ? strlen(a) : 0), lenb = (b ? strlen(b) : 0);
   return (lena >= lenb && !memcmp(PSTRE(a), PSTRE(b), lenb));
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

static inline bool
pi9_string_is_empty(const struct pi9_string *string)
{
   return pi9_cstr_is_empty(string->data);
}

static inline bool
pi9_string_ends_with_cstr(const struct pi9_string *a, const char *cstr)
{
   const size_t len = (cstr ? strlen(cstr) : 0);
   return (a->size >= len && !memcmp(a->data + a->size - len, PSTRE(cstr), len));
}

static inline bool
pi9_string_starts_with_cstr(const struct pi9_string *a, const char *cstr)
{
   const size_t len = (cstr ? strlen(cstr) : 0);
   return (a->size >= len && !memcmp(a->data, PSTRE(cstr), len));
}

static inline bool
pi9_string_ends_with(const struct pi9_string *a, const struct pi9_string *b)
{
   return (a->size >= b->size && !memcmp(a->data + a->size - b->size, PSTRE(b->data), b->size));
}

static inline bool
pi9_string_starts_with(const struct pi9_string *a, const struct pi9_string *b)
{
   return (a->size >= b->size && !memcmp(PSTRE(a->data), PSTRE(b->data), b->size));
}

static inline bool
pi9_string_eq(const struct pi9_string *a, const struct pi9_string *b)
{
   return (a->data == b->data) || (a->size == b->size && !memcmp(PSTRE(a->data), PSTRE(b->data), a->size));
}

static inline bool
pi9_string_eq_cstr(const struct pi9_string *a, const char *cstr)
{
   const size_t len = (cstr ? strlen(cstr) : 0);
   return (len == a->size) && (cstr == a->data || !memcmp(PSTRE(a->data), PSTRE(cstr), a->size));
}

#undef PSTRE

void pi9_string_release(struct pi9_string *string);
bool pi9_string_set_cstr(struct pi9_string *string, const char *data, bool is_heap);
bool pi9_string_set_cstr_with_length(struct pi9_string *string, const char *data, size_t len, bool is_heap);
bool pi9_string_set(struct pi9_string *string, const struct pi9_string *other, bool is_heap);

#if __GNUC__
__attribute__((format(printf, 2, 3)))
#endif
bool pi9_string_set_format(struct pi9_string *string, const char *fmt, ...);
bool pi9_string_set_varg(struct pi9_string *string, const char *fmt, va_list args);

#endif /* __pi9_string_h__ */
