#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "pi9.h"
#include "chck/buffer/buffer.h"

#define VERBOSE true
#define MAXWELEM 16

static const uint16_t NOTAG = (uint16_t)~0;

static const uint32_t HDRSZ = 7;      // size of header
static const uint32_t QIDSZ = 13;     // size of serialized pi9_qid
static const uint32_t STATHDRSZ = 47; // size of serialized pi9_stat, until the variable length data

struct pi9_stream {
   struct chck_buffer out, in;
};

enum op {
   OPFIRST,
   Tversion = 0x64,
   Rversion,
   Tauth = 0x66,
   Rauth,
   Tattach = 0x68,
   Rattach,
   Terror = 0x6A, // illegal
   Rerror,
   Tflush = 0x6C,
   Rflush,
   Twalk = 0x6E,
   Rwalk,
   Topen = 0x70,
   Ropen,
   Tcreate = 0x72,
   Rcreate,
   Tread = 0x74,
   Rread,
   Twrite = 0x76,
   Rwrite,
   Tclunk = 0x78,
   Rclunk,
   Tremove = 0x7A,
   Rremove,
   Tstat = 0x7C,
   Rstat,
   Twstat = 0x7E,
   Rwstat,
   OPLAST,
};

#define DECOP(x) static bool op_##x(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
DECOP(Tversion);
DECOP(Tauth);
DECOP(Tattach);
DECOP(Tflush);
DECOP(Twalk);
DECOP(Topen);
DECOP(Tcreate);
DECOP(Tread);
DECOP(Twrite);
DECOP(Tclunk);
DECOP(Tremove);
DECOP(Tstat);
DECOP(Twstat);
#undef DECOP

static struct {
   size_t msz;
   bool (*cb)(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream);
} ops[] = {
   [Tversion] = { 6, op_Tversion },
   [Tauth] = { 8, op_Tauth },
   [Terror] = { 0, NULL }, // invalid
   [Tflush] = { 2, op_Tflush },
   [Tattach] = { 12, op_Tattach },
   [Twalk] = { 10, op_Twalk },
   [Topen] = { 5, op_Topen },
   [Tcreate] = { 11, op_Tcreate },
   [Tread] = { 16, op_Tread },
   [Twrite] = { 16, op_Twrite },
   [Tclunk] = { 4, op_Tclunk },
   [Tremove] = { 4, op_Tremove },
   [Tstat] = { 4, op_Tstat },
   [Twstat] = { 6, op_Twstat },
};

static const struct {
   const char *msg;
   size_t size;
} errors[PI9_ERR_LAST] = {
#define MSG(x) { x, sizeof(x) }
   MSG("Could not read message."),
   MSG("Could not write message."),
   MSG("Authentication unnecessary."),
   MSG("File is not a directory."),
   MSG("No such file or directory."),
   MSG("Fid already in user."),
   MSG("Operation not allowed."),
   MSG("Unknown op code."),
   MSG("Out of memory."),
#undef MSG
};

static inline bool
write_qid(struct pi9_qid *qid, struct pi9_stream *stream)
{
   return (chck_buffer_write_int(&qid->type, sizeof(qid->type), &stream->out) &&
           chck_buffer_write_int(&qid->vers, sizeof(qid->vers), &stream->out) &&
           chck_buffer_write_int(&qid->path, sizeof(qid->path), &stream->out));
}

static inline bool
read_qid(struct pi9_qid *qid, struct pi9_stream *stream)
{
   return (chck_buffer_read_int(&qid->type, sizeof(qid->type), &stream->in) &&
           chck_buffer_read_int(&qid->vers, sizeof(qid->vers), &stream->in) &&
           chck_buffer_read_int(&qid->path, sizeof(qid->path), &stream->in));
}

static inline bool
read_stat(struct pi9_stat *stat, struct pi9_stream *stream)
{
   uint16_t size;
   if (!chck_buffer_read_int(&size, sizeof(size), &stream->in) ||
       !chck_buffer_read_int(&stat->type, sizeof(stat->type), &stream->in) ||
       !chck_buffer_read_int(&stat->dev, sizeof(stat->dev), &stream->in) ||
       !read_qid(&stat->qid, stream) ||
       !chck_buffer_read_int(&stat->mode, sizeof(stat->mode), &stream->in) ||
       !chck_buffer_read_int(&stat->atime, sizeof(stat->atime), &stream->in) ||
       !chck_buffer_read_int(&stat->mtime, sizeof(stat->mtime), &stream->in) ||
       !chck_buffer_read_int(&stat->length, sizeof(stat->length), &stream->in))
      return false;

   struct pi9_string *fields[4] = { &stat->name, &stat->uid, &stat->gid, &stat->muid };
   for (uint32_t i = 0; i < 4; ++i) {
      uint16_t len;
      if (!chck_buffer_read_int(&len, sizeof(len), &stream->in))
         return false;

      pi9_string_set_cstr_with_length(fields[i], stream->in.curpos, len, false);
   }

   return true;
}

static bool
op_Tversion(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   // tag should always be NOTAG in version messages
   if (tag != NOTAG)
      goto err_not_allowed;

   uint32_t msize;
   uint16_t vsize;
   if (!chck_buffer_read_int(&msize, sizeof(msize), &stream->in) ||
       !chck_buffer_read_int(&vsize, sizeof(vsize), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Tversion %u %u\n", tag, msize);
#endif

   struct pi9_string version = {0};
   pi9_string_set_cstr_with_length(&version, stream->in.curpos, vsize, false);

   // A successful version request initializes the connection.
   // All outstanding I/O on the connection is aborted; all active fids are freed (`clunked') automatically.
   // The set of messages between version requests is called a session.

   // FIXME: ↑ we need to tell higher level to abort all outstanding I/O

   // honor the buffer size request
   pi9->msize = (msize > 0 ? msize : pi9->msize);

   // only support 9P2000, maybe 9P2000.L later, .u probably never
   if (!pi9_string_eq_cstr(&version, "9P2000")) {
      static const char *preferred = "9P2000";
      const char *reply = (pi9_string_starts_with_cstr(&version, "9P") ? preferred : "unknown");
      vsize = strlen(reply);
      const uint32_t size = HDRSZ + sizeof(msize) + sizeof(vsize) + vsize;
      if (!chck_buffer_write_int(&size, sizeof(size), &stream->out) ||
          !chck_buffer_write_int((uint8_t[]){Rversion}, sizeof(uint8_t), &stream->out) ||
          !chck_buffer_write_int(&tag, sizeof(tag), &stream->out) ||
          !chck_buffer_write_int(&msize, sizeof(msize), &stream->out) ||
          !chck_buffer_write_string_of_type(reply, vsize, sizeof(uint16_t), &stream->out))
         goto err_write;
   } else {
      const size_t size = HDRSZ + sizeof(msize) + sizeof(vsize) + vsize;
      if (chck_buffer_write(stream->in.buffer, 1, size, &stream->out) != size)
         goto err_write;

      *(uint8_t*)(stream->in.buffer + sizeof(uint32_t)) = Rversion;
   }

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
err_not_allowed:
   pi9_write_error(tag, PI9_ERR_NOT_ALLOWED, stream);
   return false;
}

static bool
op_Tauth(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint32_t afid;
   if (!chck_buffer_read_int(&afid, sizeof(afid), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Tauth %u %u\n", tag, afid);
#endif

   uint16_t usize;
   if (!chck_buffer_read_int(&usize, sizeof(usize), &stream->in))
      goto err_read;

   struct pi9_string uname = {0};
   pi9_string_set_cstr_with_length(&uname, stream->in.curpos, usize, false);
   chck_buffer_seek(&stream->in, usize, SEEK_CUR);

   uint16_t asize;
   if (!chck_buffer_read_int(&asize, sizeof(asize), &stream->in))
      goto err_read;

   struct pi9_string aname = {0};
   pi9_string_set_cstr_with_length(&aname, stream->in.curpos, asize, false);

   struct pi9_qid *qid = NULL;
   if (pi9->procs.auth && !pi9->procs.auth(pi9, tag, afid, &uname, &aname, &qid))
      return false;

   if (!qid)
      goto err_no_auth;

   const uint32_t size = HDRSZ + QIDSZ;
   if (!chck_buffer_write_int(&size, sizeof(size), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Rauth}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out) ||
       !write_qid(qid, stream))
      goto err_write;

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
err_no_auth:
   pi9_write_error(tag, PI9_ERR_NO_AUTH, stream);
   return false;
}

static bool
op_Tattach(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint32_t fid, afid;
   if (!chck_buffer_read_int(&fid, sizeof(fid), &stream->in) ||
       !chck_buffer_read_int(&afid, sizeof(afid), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Tattach %u %u %u\n", tag, fid, afid);
#endif

   uint16_t usize;
   if (!chck_buffer_read_int(&usize, sizeof(usize), &stream->in))
      goto err_read;

   struct pi9_string uname = {0};
   pi9_string_set_cstr_with_length(&uname, stream->in.curpos, usize, false);
   chck_buffer_seek(&stream->in, usize, SEEK_CUR);

   uint16_t asize;
   if (!chck_buffer_read_int(&asize, sizeof(asize), &stream->in))
      goto err_read;

   struct pi9_string aname = {0};
   pi9_string_set_cstr_with_length(&aname, stream->in.curpos, asize, false);

   struct pi9_qid *qid = NULL;
   if (pi9->procs.attach && !pi9->procs.attach(pi9, tag, fid, afid, &uname, &aname, &qid))
      return false;

   const uint32_t size = HDRSZ + QIDSZ;
   if (!chck_buffer_write_int(&size, sizeof(size), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Rattach}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out) ||
       !write_qid(qid, stream))
      goto err_write;

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
}

static bool
op_Tflush(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint16_t oldtag;
   if (!chck_buffer_read_int(&oldtag, sizeof(oldtag), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Tflush %u %u\n", tag, oldtag);
#endif

   if (pi9->procs.flush && !pi9->procs.flush(pi9, tag, oldtag))
      return false;

   // The server should answer the flush message immediately.
   // If it recognizes oldtag as the tag of a pending transaction, it should abort any pending response and discard that tag.
   // In either case, it should respond with an Rflush echoing the tag (not oldtag) of the Tflush message.
   // A Tflush can never be responded to by an Rerror message.

   if (!chck_buffer_write_int(&HDRSZ, sizeof(HDRSZ), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Rflush}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out))
      goto err_write;

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
}

static bool
op_Twalk(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint16_t nwname;
   uint32_t fid, newfid;
   if (!chck_buffer_read_int(&fid, sizeof(fid), &stream->in) ||
       !chck_buffer_read_int(&newfid, sizeof(newfid), &stream->in) ||
       !chck_buffer_read_int(&nwname, sizeof(nwname), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Twalk %u %u %u %u\n", tag, fid, newfid, nwname);
#endif

   if (nwname > MAXWELEM)
      goto err_not_allowed;

   struct pi9_string walks[MAXWELEM] = {{0}};
   for (uint32_t i = 0; i < nwname; ++i) {
      uint16_t len;
      if (!chck_buffer_read_int(&len, sizeof(len), &stream->in))
         goto err_read;

      pi9_string_set_cstr_with_length(&walks[i], stream->in.curpos, len, false);
   }

   uint16_t nwqid = 0;
   struct pi9_qid *qids[MAXWELEM];
   if (pi9->procs.walk && !pi9->procs.walk(pi9, tag, fid, newfid, nwname, walks, qids, &nwqid))
      return false;

   // must be always less or equal
   assert(nwqid <= nwname);

   const uint32_t size = HDRSZ + sizeof(nwqid) + nwqid * QIDSZ;
   if (!chck_buffer_write_int(&size, sizeof(size), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Rwalk}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out) ||
       !chck_buffer_write_int(&nwqid, sizeof(nwqid), &stream->out))
      goto err_write;

   for (uint32_t i = 0; i < nwqid; ++i) {
      if (!write_qid(qids[i], stream))
         goto err_write;
   }

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
err_not_allowed:
   pi9_write_error(tag, PI9_ERR_NOT_ALLOWED, stream);
   return false;
}

static bool
op_Topen(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint8_t mode;
   uint32_t fid;
   if (!chck_buffer_read_int(&fid, sizeof(fid), &stream->in) ||
       !chck_buffer_read_int(&mode, sizeof(mode), &stream->in))
      goto err_read;

   // All other bits in mode should be zero
   // ↑ Means that I should validate the mode for unknown bits to p9 protocol

#if VERBOSE
   fprintf(stderr, "Topen %u %u %u\n", tag, fid, mode);
#endif

   uint32_t iounit = 0;
   struct pi9_qid *qid = NULL;
   if (pi9->procs.open && !pi9->procs.open(pi9, tag, fid, mode, &qid, &iounit))
      return false;

   if (!qid)
      goto err_not_allowed;

   const uint32_t size = HDRSZ + QIDSZ + sizeof(iounit);
   if (!chck_buffer_write_int(&size, sizeof(size), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Ropen}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out) ||
       !write_qid(qid, stream) ||
       !chck_buffer_write_int(&iounit, sizeof(iounit), &stream->out))
      goto err_write;

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
err_not_allowed:
   pi9_write_error(tag, PI9_ERR_NOT_ALLOWED, stream);
   return false;
}

static bool
op_Tcreate(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint32_t fid;
   uint16_t nsize;
   if (!chck_buffer_read_int(&fid, sizeof(fid), &stream->in) ||
       !chck_buffer_read_int(&nsize, sizeof(nsize), &stream->in))
      goto err_read;

   struct pi9_string name = {0};
   pi9_string_set_cstr_with_length(&name, stream->in.curpos, nsize, false);

   uint8_t mode;
   uint32_t perm;
   if (!chck_buffer_read_int(&perm, sizeof(perm), &stream->in) ||
       !chck_buffer_read_int(&mode, sizeof(mode), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Tcreate %u %u\n", tag, fid);
#endif

   // The names . and .. are special; it is illegal to create files with these names.
   if (pi9_string_eq_cstr(&name, ".") || pi9_string_eq_cstr(&name, ".."))
      goto err_not_allowed;

   uint32_t iounit = 0;
   struct pi9_qid *qid = NULL;
   if (pi9->procs.create && !pi9->procs.create(pi9, tag, fid, &name, perm, mode, &qid, &iounit))
      return false;

   if (!qid)
      goto err_not_allowed;

   const uint32_t size = HDRSZ + QIDSZ + sizeof(iounit);
   if (!chck_buffer_write_int(&size, sizeof(size), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Rcreate}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out) ||
       !write_qid(qid, stream) ||
       !chck_buffer_write_int(&iounit, sizeof(iounit), &stream->out))
      goto err_write;

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
err_not_allowed:
   pi9_write_error(tag, PI9_ERR_NOT_ALLOWED, stream);
   return false;
}

static bool
op_Tread(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint64_t offset;
   uint32_t fid, count;
   if (!chck_buffer_read_int(&fid, sizeof(fid), &stream->in) ||
       !chck_buffer_read_int(&offset, sizeof(offset), &stream->in) ||
       !chck_buffer_read_int(&count, sizeof(count), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Tread %u %u %"PRIu64" %u\n", tag, fid, offset, count);
#endif

   chck_buffer_seek(&stream->out, HDRSZ + sizeof(uint32_t), SEEK_SET);
   void *start = stream->out.curpos;

   if (pi9->procs.read && !pi9->procs.read(pi9, tag, fid, offset, count))
      return false;

   const uint32_t sbufsz = (offset != 0 ? 0 : (stream->out.curpos - start));
   const uint32_t size = HDRSZ + sizeof(sbufsz) + sbufsz;
   chck_buffer_seek(&stream->out, 0, SEEK_SET);
   if (!chck_buffer_write_int(&size, sizeof(size), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Rread}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out) ||
       !chck_buffer_write_int(&sbufsz, sizeof(sbufsz), &stream->out))
      goto err_write;

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
}

static bool
op_Twrite(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint64_t offset;
   uint32_t fid, count;
   if (!chck_buffer_read_int(&fid, sizeof(fid), &stream->in) ||
       !chck_buffer_read_int(&offset, sizeof(offset), &stream->in) ||
       !chck_buffer_read_int(&count, sizeof(count), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Twrite %u %"PRIu64" %u\n", fid, offset, count);
#endif

   if (pi9->procs.write && !pi9->procs.write(pi9, tag, fid, offset, count, (count > 0 ? stream->in.curpos : NULL)))
      return false;

   const uint32_t size = HDRSZ + sizeof(count);
   if (!chck_buffer_write_int(&size, sizeof(size), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Rwrite}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out) ||
       !chck_buffer_write_int(&count, sizeof(count), &stream->out))
      goto err_write;

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
}

static bool
op_Tclunk(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint32_t fid;
   if (!chck_buffer_read_int(&fid, sizeof(fid), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Tclunk %u %u\n", tag, fid);
#endif

   if (pi9->procs.clunk && !pi9->procs.clunk(pi9, tag, fid))
      return false;

   if (!chck_buffer_write_int(&HDRSZ, sizeof(HDRSZ), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Rclunk}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out))
      goto err_write;

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
}

static bool
op_Tremove(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint32_t fid;
   if (!chck_buffer_read_int(&fid, sizeof(fid), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Tremove %u %u\n", tag, fid);
#endif

   if (pi9->procs.remove && !pi9->procs.remove(pi9, tag, fid))
      return false;

   if (!chck_buffer_write_int(&HDRSZ, sizeof(HDRSZ), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Rremove}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out))
      goto err_write;

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
}

static bool
op_Tstat(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint32_t fid;
   if (!chck_buffer_read_int(&fid, sizeof(fid), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Tstat %u %u\n", tag, fid);
#endif

   chck_buffer_seek(&stream->out, HDRSZ + sizeof(uint16_t), SEEK_SET);
   void *start = stream->out.curpos;

   struct pi9_stat *stat = NULL;
   if (pi9->procs.stat && !pi9->procs.stat(pi9, tag, fid, &stat))
      return false;

   if (stat && !pi9_write_stat(stat, stream))
      goto err_write;

   // too big
   if (stream->out.curpos - start > 0xFFFF)
      goto err_write;

   const uint16_t sbufsz = (stream->out.curpos - start);
   const uint32_t size = HDRSZ + sizeof(sbufsz) + sbufsz;
   chck_buffer_seek(&stream->out, 0, SEEK_SET);
   if (!chck_buffer_write_int(&size, sizeof(size), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Rstat}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out) ||
       !chck_buffer_write_int(&sbufsz, sizeof(sbufsz), &stream->out))
      goto err_write;

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
}

static bool
op_Twstat(struct pi9 *pi9, uint16_t tag, struct pi9_stream *stream)
{
   uint32_t fid;
   uint16_t sbufsz;
   if (!chck_buffer_read_int(&fid, sizeof(fid), &stream->in) ||
       !chck_buffer_read_int(&sbufsz, sizeof(sbufsz), &stream->in))
      goto err_read;

#if VERBOSE
   fprintf(stderr, "Twstat %u %u %u\n", tag, fid, sbufsz);
#endif

   struct pi9_stat stat = {0};
   if (!read_stat(&stat, stream))
      goto err_read;

   if (pi9->procs.twstat && !pi9->procs.twstat(pi9, tag, fid, &stat))
      return false;

   if (!chck_buffer_write_int(&HDRSZ, sizeof(HDRSZ), &stream->out) ||
       !chck_buffer_write_int((uint8_t[]){Rwstat}, sizeof(uint8_t), &stream->out) ||
       !chck_buffer_write_int(&tag, sizeof(tag), &stream->out))
      goto err_write;

   return true;

err_read:
   pi9_write_error(tag, PI9_ERR_READ, stream);
   return false;
err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
}

static inline bool
call_op(struct pi9 *pi9, enum op op, uint16_t tag, struct pi9_stream *stream)
{
   // check opcode range, and only allow T opcodes (% 2), also check that message meets minimum size
   if (op <= OPFIRST || op >= OPLAST || op % 2 != 0 || stream->in.size < ops[op].msz)
      goto err_unknown_op;

   if (op == Terror) {
#if VERBOSE
      fprintf(stderr, "Got error from the client.\n");
#endif
      return true;
   }

   if (stream->out.size < ops[op].msz && !chck_buffer_resize(&stream->out, ops[op].msz))
      goto err_write;

   return ops[op].cb(pi9, tag, stream);

err_write:
   pi9_write_error(tag, PI9_ERR_WRITE, stream);
   return false;
err_unknown_op:
   pi9_write_error(tag, PI9_ERR_UNKNOWN_OP, stream);
   return false;
}

static bool
read_msg(struct pi9 *pi9, int32_t fd, struct pi9_stream *stream)
{
   assert(pi9 && fd >= 0);

   if (chck_buffer_fill_from_fd(fd, 1, pi9->msize, &stream->in) < HDRSZ)
      return false;

   uint32_t size;
   if (!chck_buffer_read_int(&size, sizeof(size), &stream->in) || size < HDRSZ)
      return false;

   if (stream->in.size < size) {
      const size_t to_read = size - stream->in.size;
      chck_buffer_seek(&stream->in, 0, SEEK_END);
      if (chck_buffer_fill_from_fd(fd, 1, to_read, &stream->in) < to_read)
         return false;
      chck_buffer_seek(&stream->in, sizeof(size), SEEK_SET);
   }

   uint8_t op;
   uint16_t tag;
   if (!chck_buffer_read_int(&op, sizeof(uint8_t), &stream->in) ||
       !chck_buffer_read_int(&tag, sizeof(uint16_t), &stream->in))
      return false;

#if VERBOSE
   fprintf(stderr, "Read message of size: %u (%u : %u)\n", size, op, tag);
   for (uint32_t i = 0; i < size; ++i)
      putc(*(char*)(stream->in.buffer + i), stderr);
   putc('\n', stderr);
#endif

   return call_op(pi9, op, tag, stream);
}

static inline bool
write_msg(int32_t fd, struct pi9_stream *stream)
{
   assert(fd >= 0 && stream->out.buffer);
   const uint32_t size = *(uint32_t*)stream->out.buffer;
#if VERBOSE
   fprintf(stderr, "Write message of size: %u\n", size);
#endif
   return write(fd, stream->out.buffer, size) == size;
}

bool
pi9_write_stat(struct pi9_stat *stat, struct pi9_stream *stream)
{
   const size_t size = STATHDRSZ + stat->name.size + stat->uid.size + stat->gid.size + stat->muid.size;

   // too big
   if (size > 0xFFFF)
      return false;

   const uint16_t size16 = size;
   return (chck_buffer_write_int(&size16, sizeof(size16), &stream->out) &&
           chck_buffer_write_int(&stat->type, sizeof(stat->type), &stream->out) &&
           chck_buffer_write_int(&stat->dev, sizeof(stat->dev), &stream->out) &&
           write_qid(&stat->qid, stream) &&
           chck_buffer_write_int(&stat->mode, sizeof(stat->mode), &stream->out) &&
           chck_buffer_write_int(&stat->atime, sizeof(stat->atime), &stream->out) &&
           chck_buffer_write_int(&stat->mtime, sizeof(stat->mtime), &stream->out) &&
           chck_buffer_write_int(&stat->length, sizeof(stat->length), &stream->out) &&
           chck_buffer_write_string_of_type(stat->name.data, stat->name.size, sizeof(uint16_t), &stream->out) &&
           chck_buffer_write_string_of_type(stat->uid.data, stat->uid.size, sizeof(uint16_t), &stream->out) &&
           chck_buffer_write_string_of_type(stat->gid.data, stat->gid.size, sizeof(uint16_t), &stream->out) &&
           chck_buffer_write_string_of_type(stat->muid.data, stat->muid.size, sizeof(uint16_t), &stream->out));
}

size_t
pi9_write(const void *src, size_t size, size_t nmemb, struct pi9_stream *stream)
{
   return chck_buffer_write(src, size, nmemb, &stream->out);
}

void
pi9_stat_release(struct pi9_stat *stat)
{
   if (!stat)
      return;

   struct pi9_string *fields[4] = { &stat->name, &stat->uid, &stat->gid, &stat->muid };
   for (uint32_t i = 0; i < 4; ++i)
      pi9_string_release(fields[i]);
}

bool
pi9_process(struct pi9 *pi9, int32_t fd)
{
   assert(pi9 && fd >= 0 && pi9->stream);

   chck_buffer_seek(&pi9->stream->in, 0, SEEK_SET);
   chck_buffer_seek(&pi9->stream->out, 0, SEEK_SET);

   bool ret = true;
   if (!read_msg(pi9, fd, pi9->stream)) {
      if (pi9->stream->out.curpos == pi9->stream->out.buffer)
         pi9_write_error(NOTAG, PI9_ERR_READ, pi9->stream);
      ret = false;
   }

   if (!write_msg(fd, pi9->stream)) {
      pi9_write_error(NOTAG, PI9_ERR_WRITE, pi9->stream);
      write_msg(fd, pi9->stream);
      ret = false;
   }

   return ret;
}

void
pi9_release(struct pi9 *pi9)
{
   if (!pi9)
      return;

   chck_buffer_release(&pi9->stream->out);
   chck_buffer_release(&pi9->stream->in);
   free(pi9->stream);
   memset(pi9, 0, sizeof(struct pi9));
}

bool
pi9_init(struct pi9 *pi9, uint32_t msize, struct pi9_procs *procs, void *userdata)
{
   assert(pi9);
   memset(pi9, 0, sizeof(struct pi9));
   memcpy(&pi9->procs, procs, sizeof(struct pi9_procs));
   pi9->msize = (msize > 0 ? msize : 8192);
   pi9->userdata = userdata;

   if (!(pi9->stream = calloc(1, sizeof(struct pi9_stream))))
      goto fail;

   if (!chck_buffer(&pi9->stream->in, pi9->msize, CHCK_ENDIANESS_LITTLE))
      goto fail;

   if (!chck_buffer(&pi9->stream->out, pi9->msize, CHCK_ENDIANESS_LITTLE))
      goto fail;

   return true;

fail:
   pi9_release(pi9);
   return false;
}

#undef pi9_write_error

void
pi9_write_error(uint16_t tag, enum pi9_error error, struct pi9_stream *stream)
{
   assert(stream);
   const int32_t size = HDRSZ + sizeof(uint16_t) + errors[error].size;
   chck_buffer_seek(&stream->out, 0, SEEK_SET);
   chck_buffer_write_int(&size, sizeof(size), &stream->out);
   chck_buffer_write_int((uint8_t[]){ Rerror }, sizeof(uint8_t), &stream->out);
   chck_buffer_write_int(&tag, sizeof(tag), &stream->out);
   chck_buffer_write_string_of_type(errors[error].msg, errors[error].size, sizeof(uint16_t), &stream->out);
   fprintf(stderr, "%s\n", errors[error].msg);
}
