
/*
 * Copyright (C) CloudFlare, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <brotli.h>

typedef struct {
    ngx_flag_t           enable;
    ngx_hash_t           types;
    ngx_bufs_t           bufs;
    ngx_int_t            level;
    ssize_t              min_length;
    ngx_array_t         *types_keys;
} ngx_http_brotli_conf_t;


typedef struct {
    ngx_chain_t         *in;
    ngx_chain_t         *free;
    ngx_chain_t         *busy;
    ngx_chain_t         *out;
    ngx_chain_t        **last_out;

    ngx_chain_t         *copied;
    ngx_chain_t         *copy_buf;

    ngx_buf_t           *in_buf;
    ngx_buf_t           *out_buf;
    ngx_int_t            bufs;

    unsigned             flush:4;
    unsigned             redo:1;
    unsigned             done:1;
    unsigned             nomem:1;
    unsigned             br:1;   // Indicates if "br" or "brotli"

    b_stream             bstream;
    ngx_http_request_t  *request;
} ngx_http_brotli_ctx_t;

static ngx_int_t ngx_http_brotli_filter_start(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx);
static ngx_int_t ngx_http_brotli_filter_add_data(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx);
static ngx_int_t ngx_http_brotli_filter_get_buf(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx);
static ngx_int_t ngx_http_brotli_filter_compress(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx);
static ngx_int_t ngx_http_brotli_filter_end(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx);
static void ngx_http_brotli_filter_free_copy_buf(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx);

static ngx_int_t ngx_http_brotli_filter_init(ngx_conf_t *cf);
static void *ngx_http_brotli_create_conf(ngx_conf_t *cf);
static char *ngx_http_brotli_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_conf_num_bounds_t  ngx_http_brotli_comp_level_bounds = {
    ngx_conf_check_num_bounds, 1, 11
};

static ngx_command_t  ngx_http_brotli_filter_commands[] = {

    { ngx_string("brotli"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brotli_conf_t, enable),
      NULL },

    { ngx_string("brotli_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brotli_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("brotli_comp_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brotli_conf_t, level),
      &ngx_http_brotli_comp_level_bounds },

    { ngx_string("brotli_min_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brotli_conf_t, min_length),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_brotli_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_brotli_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_brotli_create_conf,           /* create location configuration */
    ngx_http_brotli_merge_conf             /* merge location configuration */
};


ngx_module_t  ngx_http_brotli_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_brotli_filter_module_ctx,    /* module context */
    ngx_http_brotli_filter_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_int_t
ngx_http_brotli_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t         *h, *ae;
    ngx_http_brotli_ctx_t   *ctx;
    ngx_http_brotli_conf_t  *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http brotli header filter");

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brotli_filter_module);

    if (!conf->enable
        || (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_FORBIDDEN
            && r->headers_out.status != NGX_HTTP_NOT_FOUND)
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || (r->headers_out.content_length_n != -1
            && r->headers_out.content_length_n < conf->min_length)
        || ngx_http_test_content_type(r, &conf->types) == NULL
        || r->header_only)
    {
        return ngx_http_next_header_filter(r);
    }

    /* Check that brotli is supported. We do not check possible q value
     * if brotli is supported it takes precendence over gzip if size >
     * brotli_min_length */
    ae = r->headers_in.accept_encoding;
    /* Since there is no reason for the br string to be present
     * unless brotli is accepted either as "br" or "brotli" we
     * just check for "br" */
    if (!ngx_strstrn(ae->value.data, "br", 1)) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_brotli_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_strstrn(ae->value.data, "brotli", 5)) {
        ctx->br = 0;
    } else {
        ctx->br = 1;
    }
#if (NGX_HTTP_GZIP)
    r->gzip_vary = 1;
    /* Make sure gzip does not execute */
    r->gzip_tested = 1;
    r->gzip_ok = 0;
#endif

    ngx_http_set_ctx(r, ctx, ngx_http_brotli_filter_module);

    ctx->request = r;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Content-Encoding");
    if (ctx->br) {
        ngx_str_set(&h->value, "br");
    } else {
        ngx_str_set(&h->value, "brotli");
    }
    r->headers_out.content_encoding = h;

    r->main_filter_need_in_memory = 1;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}

/* The brotli body is almost identical to gzip body */
static ngx_int_t
ngx_http_brotli_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                    rc;
    ngx_uint_t             flush;
    ngx_chain_t           *cl;
    ngx_http_brotli_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brotli_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http brotli filter");

    if (ctx->bstream.compressor == NULL) {
        if (ngx_http_brotli_filter_start(r, ctx) != NGX_OK) {
            goto failed;
        }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http brotli compressor allocated");
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            goto failed;
        }
        r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;
    }

    if (ctx->nomem) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http brotli nomem");

        /* flush busy buffers */
        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            goto failed;
        }

        cl = NULL;

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_brotli_filter_module);
        ctx->nomem = 0;
        flush = 0;
    } else {
        flush = ctx->busy ? 1 : 0;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http brotli set flush %d", flush);
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            /* cycle while there is data to feed botli and ... */

            rc = ngx_http_brotli_filter_add_data(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            /* ... there are buffers to write brotli output */

            rc = ngx_http_brotli_filter_get_buf(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }


            rc = ngx_http_brotli_filter_compress(r, ctx);

            if (rc == NGX_OK) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }

            /* rc == NGX_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            ngx_http_brotli_filter_free_copy_buf(r, ctx);
            return ctx->busy ? NGX_AGAIN : NGX_OK;
        }

        rc = ngx_http_next_body_filter(r, ctx->out);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        ngx_http_brotli_filter_free_copy_buf(r, ctx);

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_brotli_filter_module);
        ctx->last_out = &ctx->out;

        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            return rc;
        }
    }

    /* unreachable */

failed:

    ctx->done = 1;

    ngx_http_brotli_filter_free_copy_buf(r, ctx);
    freeBrotli(ctx->bstream.compressor);
    ctx->bstream.compressor = NULL;

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_brotli_filter_start(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx)
{
    ngx_http_brotli_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brotli_filter_module);

    ctx->bstream.avail_in = 0;
    ctx->bstream.avail_out = 0;
    ctx->bstream.buffered_out = 0;
    ctx->bstream.finish = 0;
    ctx->bstream.compressor = newBrotli(conf->level);
    ctx->last_out = &ctx->out;
    ctx->flush = B_NO_FLUSH;

    return NGX_OK;
}


static ngx_int_t
ngx_http_brotli_filter_add_data(ngx_http_request_t *r, ngx_http_brotli_ctx_t *ctx)
{
    if (ctx->bstream.avail_in || ctx->flush != B_NO_FLUSH || ctx->redo) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brotli in: %p", ctx->in);

    if (ctx->in == NULL) {
        return NGX_DECLINED;
    }

    if (ctx->copy_buf) {
        ctx->copy_buf->next = ctx->copied;
        ctx->copied = ctx->copy_buf;
        ctx->copy_buf = NULL;
    }

    ctx->in_buf = ctx->in->buf;

    if (ctx->in_buf->tag == (ngx_buf_tag_t) &ngx_http_brotli_filter_module) {
        ctx->copy_buf = ctx->in;
    }

    ctx->in = ctx->in->next;

    ctx->bstream.next_in = ctx->in_buf->pos;
    ctx->bstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brotli in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->bstream.next_in, ctx->bstream.avail_in);

    if (ctx->in_buf->last_buf) {
        ctx->flush = B_FINISH;
    } else if (ctx->in_buf->flush) {
        ctx->flush = B_SYNC_FLUSH;
    }

    if (!ctx->bstream.avail_in && ctx->flush == B_NO_FLUSH) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_brotli_filter_get_buf(ngx_http_request_t *r, ngx_http_brotli_ctx_t *ctx)
{
    ngx_http_brotli_conf_t  *conf;

    if (ctx->bstream.avail_out) {
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brotli_filter_module);

    if (ctx->free) {
        ctx->out_buf = ctx->free->buf;
        ctx->free = ctx->free->next;

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = ngx_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_brotli_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
        return NGX_DECLINED;
    }

    ctx->bstream.next_out = ctx->out_buf->pos;
    ctx->bstream.avail_out = conf->bufs.size;

    return NGX_OK;
}


static ngx_int_t
ngx_http_brotli_filter_compress(ngx_http_request_t *r, ngx_http_brotli_ctx_t *ctx)
{
    int                      rc;
    ngx_buf_t               *b;
    ngx_chain_t             *cl;

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "brotli in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
                 ctx->bstream.next_in, ctx->bstream.next_out,
                 ctx->bstream.avail_in, ctx->bstream.avail_out,
                 ctx->flush, ctx->redo);

    rc = compress(&ctx->bstream, ctx->flush);

    if (rc != B_OK && rc != B_STREAM_END && rc != B_BUF_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "compress() failed: %d, %d", ctx->flush, rc);
        return NGX_ERROR;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brotli out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   ctx->bstream.next_in, ctx->bstream.next_out,
                   ctx->bstream.avail_in, ctx->bstream.avail_out,
                   rc);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brotli in_buf:%p pos:%p",
                   ctx->in_buf, ctx->in_buf->pos);

    if (ctx->bstream.next_in) {
        ctx->in_buf->pos = ctx->bstream.next_in;

        if (ctx->bstream.avail_in == 0) {
            ctx->bstream.next_in = NULL;
        }
    }

    ctx->out_buf->last = ctx->bstream.next_out;

    if (ctx->bstream.avail_out == 0) {

        /* brotli wants to output some more compressed data */

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        ctx->redo = 1;

        return NGX_AGAIN;
    }

    ctx->redo = 0;

    if (ctx->flush == B_SYNC_FLUSH) {

        ctx->flush = B_NO_FLUSH;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = ctx->out_buf;

        if (ngx_buf_size(b) == 0) {

            b = ngx_calloc_buf(ctx->request->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

        } else {
            ctx->bstream.avail_out = 0;
        }

        b->flush = 1;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

        return NGX_OK;
    }

    if (rc == B_STREAM_END) {
        if (ngx_http_brotli_filter_end(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }
    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_brotli_filter_end(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx)
{
    ngx_chain_t       *cl;

    freeBrotli(ctx->bstream.compressor);
    ctx->bstream.compressor = NULL;
    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = ctx->out_buf;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    ctx->out_buf->last_buf = 1;

    ctx->bstream.avail_in = 0;
    ctx->bstream.avail_out = 0;

    ctx->done = 1;

    r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

    return NGX_OK;
}


static void
ngx_http_brotli_filter_free_copy_buf(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx)
{
    ngx_chain_t  *cl;

    for (cl = ctx->copied; cl; cl = cl->next) {
        ngx_pfree(r->pool, cl->buf->start);
    }

    ctx->copied = NULL;
}


static void *
ngx_http_brotli_create_conf(ngx_conf_t *cf)
{
    ngx_http_brotli_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_brotli_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->bufs.num = 0;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->level = NGX_CONF_UNSET;
    conf->min_length = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_brotli_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_brotli_conf_t *prev = parent;
    ngx_http_brotli_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    ngx_conf_merge_value(conf->level, prev->level, 5);
    ngx_conf_merge_value(conf->min_length, prev->min_length, 16384);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_brotli_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_brotli_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_brotli_body_filter;

    return NGX_OK;
}
