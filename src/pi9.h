#ifndef __pi9_h__
#define __pi9_h__

#include <stdio.h>
#include "pi9_string.h"

static const uint32_t PI9_NOFID = (uint32_t)~0;

struct pi9_stream;

struct pi9_qid {
   uint8_t type;
   uint32_t vers;
   uint64_t path;
};

struct pi9_stat {
   uint16_t type;
   uint32_t dev;
   struct pi9_qid qid;
   uint32_t mode;
   uint32_t atime;
   uint32_t mtime;
   uint64_t length;
   struct pi9_string name;
   struct pi9_string uid;
   struct pi9_string gid;
   struct pi9_string muid;
};

struct pi9 {
   void *userdata;
   struct pi9_stream *stream;

   uint32_t msize;

   struct pi9_procs {
      bool (*auth)(struct pi9 *pi9, uint16_t tag, uint32_t afid, const struct pi9_string *uname, const struct pi9_string *aname, struct pi9_qid **qid);
      bool (*attach)(struct pi9 *pi9, uint16_t tag, uint32_t fid, uint32_t afid, const struct pi9_string *uname, const struct pi9_string *aname, struct pi9_qid **qid);
      bool (*flush)(struct pi9 *pi9, uint16_t tag, uint16_t oldtag);
      bool (*walk)(struct pi9 *pi9, uint16_t tag, uint32_t fid, uint32_t newfid, uint16_t nwname, const struct pi9_string *walks, struct pi9_qid **qids, uint16_t *out_nwqid);
      bool (*open)(struct pi9 *pi9, uint16_t tag, uint32_t fid, uint8_t mode, struct pi9_qid **out_qid, uint32_t *out_iounit);
      bool (*create)(struct pi9 *pi9, uint16_t tag, uint32_t fid, const struct pi9_string *name, uint32_t perm, uint8_t mode, struct pi9_qid **out_qid, uint32_t *out_iounit);
      bool (*read)(struct pi9 *pi9, uint16_t tag, uint32_t fid, uint64_t offset, uint32_t count);
      bool (*write)(struct pi9 *pi9, uint16_t tag, uint32_t fid, uint64_t offset, uint32_t count, const void *data);
      bool (*clunk)(struct pi9 *pi9, uint16_t tag, uint32_t fid);
      bool (*remove)(struct pi9 *pi9, uint16_t tag, uint32_t fid);
      bool (*stat)(struct pi9 *pi9, uint16_t tag, uint32_t fid, struct pi9_stat **out_stat);
      bool (*twstat)(struct pi9 *pi9, uint16_t tag, uint32_t fid, const struct pi9_stat *stat);
   } procs;
};

// from libc.h
enum {
   PI9_OREAD = 0x0000,     // open for read
   PI9_OWRITE = 0x0001,    // write
   PI9_ORDWR = 0x0002,     // read and write
   PI9_OEXEC = 0x0003,     // execute, == read but check execute permission
   PI9_OTRUNC = 0x0010,    // or'ed in (except for exec), truncate file first
   PI9_OCEXEC = 0x0020,    // or'ed in, close on exec
   PI9_ORCLOSE = 0x0040,   // or'ed in, remove on close
   PI9_ODIRECT = 0x0080,   // or'ed in, direct access
   PI9_ONONBLOCK = 0x0100, // or'ed in, non-blocking call
   PI9_OEXCL = 0x1000,     // or'ed in, exclusive use (create only)
   PI9_OLOCK = 0x2000,     // or'ed in, lock after opening
   PI9_OAPPEND = 0x4000    // or'ed in, append only
};

// bits in pi9_qid.type
enum {
   PI9_QTDIR = 0x80,     // type bit for directories
   PI9_QTAPPEND = 0x40,  // type bit for append only files
   PI9_QTEXCL = 0x20,    // type bit for exclusive use files
   PI9_QTMOUNT = 0x10,   // type bit for mounted channel
   PI9_QTAUTH = 0x08,    // type bit for authentication file
   PI9_QTTMP = 0x04,     // type bit for non-backed-up file
   PI9_QTSYMLINK = 0x02, // type bit for symbolic link
   PI9_QTFILE = 0x00     // type bits for plain file
};

// bits in pi9_stat.mode
enum {
   PI9_DMEXEC = 0x1,  // mode bit for execute permission
   PI9_DMWRITE = 0x2, // mode bit for write permission
   PI9_DMREAD = 0x4,  // mode bit for read permission

   PI9_DMDIR = 0x80000000,    // mode bit for directories
   PI9_DMAPPEND = 0x40000000, // mode bit for append only files
   PI9_DMEXCL = 0x20000000,   // mode bit for exclusive use files
   PI9_DMMOUNT = 0x10000000,  // mode bit for mounted channel
   PI9_DMAUTH = 0x08000000,   // mode bit for authentication file
   PI9_DMTMP = 0x04000000,    // mode bit for non-backed-up file
};

enum pi9_error {
   PI9_ERR_READ,
   PI9_ERR_WRITE,
   PI9_ERR_NO_AUTH,
   PI9_ERR_NOT_DIRECTORY,
   PI9_ERR_NO_FID,
   PI9_ERR_FID_IN_USE,
   PI9_ERR_NOT_ALLOWED,
   PI9_ERR_UNKNOWN_OP,
   PI9_ERR_OUT_OF_MEMORY,
   PI9_ERR_LAST,
};

bool pi9_write_stat(struct pi9_stat *stat, struct pi9_stream *stream);
void pi9_write_error(uint16_t tag, enum pi9_error error, struct pi9_stream *stream);
size_t pi9_write(const void *src, size_t size, size_t nmemb, struct pi9_stream *stream);
void pi9_stat_release(struct pi9_stat *stat);
bool pi9_process(struct pi9 *pi9, int32_t fd);
bool pi9_init(struct pi9 *pi9, uint32_t msize, struct pi9_procs *procs, void *userdata);
void pi9_release(struct pi9 *pi9);

#define pi9_write_error(t, e, o) \
{ fprintf(stderr, "%s (%s) @ %u: ", ((strrchr(__FILE__, '/') ?: __FILE__ - 1) + 1), __FUNCTION__, __LINE__); \
  pi9_write_error(t, e, o); }

#endif /* __pi9_h__ */
