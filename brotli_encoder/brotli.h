#ifndef BROTLI_H
#define BROTLI_H

#ifdef __cplusplus
extern "C" {
#endif

/* This structure enables zlib like streaming behaviour of the C wrapper */
typedef struct b_stream_s {
    unsigned char *next_in;      /* next input byte */
    unsigned long  avail_in;     /* number of bytes available at next_in */
    unsigned long  total_in;     /* total number of input bytes read so far */

    unsigned char *next_out;     /* next output byte should be put there */
    unsigned long  avail_out;    /* remaining free space at next_out */
    unsigned long  total_out;    /* total number of bytes output so far */

    void          *compressor;   /* the underlying c++ compressor */

    unsigned char *out_buff;     /* the current internal output buffer */
    unsigned long  buffered_out; /* bytes available at out_buff */
    int            finish;       /* finish started */
} b_stream;

typedef b_stream *b_streamp;

typedef enum {B_NO_FLUSH, B_SYNC_FLUSH, B_FINISH} brotliFlush;
typedef enum {B_OK, B_STREAM_END, B_BUF_ERROR} brotliRet;

void *newBrotli(int quality);
void freeBrotli(void *compressor);

brotliRet brotli_compress(b_streamp state, brotliFlush f);

#ifdef __cplusplus
}
#endif

#endif
