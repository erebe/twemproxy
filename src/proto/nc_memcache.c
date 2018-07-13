/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>

#include "../nc_core.h"
#include "nc_proto.h"
#include "nc_memcache_binary.c"

/*
 * From memcache protocol specification:
 *
 * Data stored by memcached is identified with the help of a key. A key
 * is a text string which should uniquely identify the data for clients
 * that are interested in storing and retrieving it.  Currently the
 * length limit of a key is set at 250 characters (of course, normally
 * clients wouldn't need to use such long keys); the key must not include
 * control characters or whitespace.
 */
#define MEMCACHE_MAX_KEY_LENGTH 250

/*
 * Return true, if the memcache command is a storage command, otherwise
 * return false
 */
static bool
memcache_storage(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_MC_SET:
    case MSG_REQ_MC_CAS:
    case MSG_REQ_MC_ADD:
    case MSG_REQ_MC_REPLACE:
    case MSG_REQ_MC_APPEND:
    case MSG_REQ_MC_PREPEND:
        return true;

    default:
        break;
    }

    return false;
}

/*
 * Return true, if the memcache command is a cas command, otherwise
 * return false
 */
static bool
memcache_cas(struct msg *r)
{
    if (r->type == MSG_REQ_MC_CAS) {
        return true;
    }

    return false;
}

/*
 * Return true, if the memcache command is a retrieval command, otherwise
 * return false
 */
static bool
memcache_retrieval(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_MC_GET:
    case MSG_REQ_MC_GETS:
        return true;

    default:
        break;
    }

    return false;
}

/*
 * Return true, if the memcache command is a arithmetic command, otherwise
 * return false
 */
static bool
memcache_arithmetic(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_MC_INCR:
    case MSG_REQ_MC_DECR:
        return true;

    default:
        break;
    }

    return false;
}

/*
 * Return true, if the memcache command is a delete command, otherwise
 * return false
 */
static bool
memcache_delete(struct msg *r)
{
    if (r->type == MSG_REQ_MC_DELETE) {
        return true;
    }

    return false;
}

/*
 * Return true, if the memcache command is a touch command, otherwise
 * return false
 */
static bool
memcache_touch(struct msg *r)
{
    if (r->type == MSG_REQ_MC_TOUCH) {
        return true;
    }

    return false;
}

void
memcache_parse_req(struct msg *r)
{
    struct mbuf *b;
    uint8_t *p, *m;
    uint8_t ch;
    enum {
        SW_START,
        SW_REQ_TYPE,
        SW_SPACES_BEFORE_KEY,
        SW_KEY,
        SW_SPACES_BEFORE_KEYS,
        SW_SPACES_BEFORE_FLAGS,
        SW_FLAGS,
        SW_SPACES_BEFORE_EXPIRY,
        SW_EXPIRY,
        SW_SPACES_BEFORE_VLEN,
        SW_VLEN,
        SW_SPACES_BEFORE_CAS,
        SW_CAS,
        SW_RUNTO_VAL,
        SW_VAL,
        SW_SPACES_BEFORE_NUM,
        SW_NUM,
        SW_RUNTO_CRLF,
        SW_CRLF,
        SW_NOREPLY,
        SW_AFTER_NOREPLY,
        SW_ALMOST_DONE,
        SW_SENTINEL
    } state;

    state = r->state;
    b = STAILQ_LAST(&r->mhdr, mbuf, next);

    ASSERT(r->request);
    ASSERT(!r->redis);
    ASSERT(state >= SW_START && state < SW_SENTINEL);
    ASSERT(b != NULL);
    ASSERT(b->pos <= b->last);

    /* validate the parsing maker */
    ASSERT(r->pos != NULL);
    ASSERT(r->pos >= b->pos && r->pos <= b->last);

    ASSERT(*(r->pos) == 0x80);

    struct header_t* memcached_header = (struct header_t*) r->pos;

   // r->noforward = 1;
    switch (memcached_header->opcode) {
    case Get:
    case GetQ:
        r->type = MSG_REQ_MC_GET;
        break;

    case Set:
    case SetQ:
        r->type = MSG_REQ_MC_SET;
        r->noforward = 0;
        break;

    case Add:
    case AddQ:
        r->type = MSG_REQ_MC_ADD;
        break;

    case Replace:
    case ReplaceQ:
        r->type = MSG_REQ_MC_REPLACE;
        break;

    case Touch:
        r->type = MSG_REQ_MC_TOUCH;
        break;

    case Increment:
    case IncrementQ:
        r->type = MSG_REQ_MC_INCR;
        break;

    case Decrement:
    case DecrementQ:
        r->type = MSG_REQ_MC_DECR;
        break;

    case Delete:
        r->type = MSG_REQ_MC_DELETE;
        break;

    case Prepend:
    case PrependQ:
        r->type = MSG_REQ_MC_PREPEND;
        break;

    case Append:
    case AppendQ:
        r->type = MSG_REQ_MC_APPEND;
        break;

    case Quit:
    case QuitQ:
        r->type = MSG_REQ_MC_QUIT;
        break;

    default:
       //log_error("Not handled command type %hhu", memcached_header->opcode);
        r->type = MSG_REQ_MC_GETS;
        break;
    }

    uint16_t key_length = ntohs(memcached_header->key_length);
    if(key_length > 0) {
        struct keypos* kpos = array_push(r->keys);
        if (kpos == NULL) {
            goto enomem;
        }
        kpos->start = ((uint8_t*) (memcached_header + 1)) + memcached_header->extras_length;
        kpos->end = kpos->start + key_length;
        r->narg++;
    }

    uint32_t body_length = ntohl(memcached_header->body_length);
    r->vlen = body_length - memcached_header->extras_length - key_length;
    p = ((uint8_t*)(memcached_header + 1)) + body_length - 1;

    // TODO handle case where b->last does not contains all the body length
    goto done;


    /*
     * At this point, buffer from b->pos to b->last has been parsed completely
     * but we haven't been able to reach to any conclusion. Normally, this
     * means that we have to parse again starting from the state we are in
     * after more data has been read. The newly read data is either read into
     * a new mbuf, if existing mbuf is full (b->last == b->end) or into the
     * existing mbuf.
     *
     * The only exception to this is when the existing mbuf is full (b->last
     * is at b->end) and token marker is set, which means that we have to
     * copy the partial token into a new mbuf and parse again with more data
     * read into new mbuf.
     */
    ASSERT(p == b->last);
    r->pos = p;
    r->state = state;

    if (b->last == b->end && r->token != NULL) {
        r->pos = r->token;
        r->token = NULL;
        r->result = MSG_PARSE_REPAIR;
    } else {
        r->result = MSG_PARSE_AGAIN;
    }

    log_hexdump(LOG_VERB, b->pos, mbuf_length(b), "parsed req %"PRIu64" res %d "
                "type %d state %d rpos %d of %d", r->id, r->result, r->type,
                r->state, r->pos - b->pos, b->last - b->pos);
    return;

done:
    ASSERT(r->type > MSG_UNKNOWN && r->type < MSG_SENTINEL);
    r->pos = p + 1;
    ASSERT(r->pos <= b->last);
    r->state = SW_START;
    r->result = MSG_PARSE_OK;

    log_hexdump(LOG_VERB, b->pos, mbuf_length(b), "parsed req %"PRIu64" res %d "
                "type %d state %d rpos %d of %d", r->id, r->result, r->type,
                r->state, r->pos - b->pos, b->last - b->pos);
    return;

enomem:
    r->result = MSG_PARSE_ERROR;
    r->state = state;

    log_hexdump(LOG_INFO, b->pos, mbuf_length(b), "out of memory on parse req %"PRIu64" "
                "res %d type %d state %d", r->id, r->result, r->type, r->state);

    return;

error:
    r->result = MSG_PARSE_ERROR;
    r->state = state;
    errno = EINVAL;

    log_hexdump(LOG_INFO, b->pos, mbuf_length(b), "parsed bad req %"PRIu64" "
                "res %d type %d state %d", r->id, r->result, r->type,
                r->state);
}

void
memcache_parse_rsp(struct msg *r)
    // TODO handle case where b->last does not contains all the body length
{
    struct mbuf *b;
    uint8_t *p, *m;
    uint8_t ch;
    enum {
        SW_START,
        SW_RSP_NUM,
        SW_RSP_STR,
        SW_SPACES_BEFORE_KEY,
        SW_KEY,
        SW_SPACES_BEFORE_FLAGS,     /* 5 */
        SW_FLAGS,
        SW_SPACES_BEFORE_VLEN,
        SW_VLEN,
        SW_RUNTO_VAL,
        SW_VAL,                     /* 10 */
        SW_VAL_LF,
        SW_END,
        SW_RUNTO_CRLF,
        SW_CRLF,
        SW_ALMOST_DONE,             /* 15 */
        SW_SENTINEL
    } state;

    state = r->state;
    b = STAILQ_LAST(&r->mhdr, mbuf, next);

    ASSERT(!r->request);
    ASSERT(!r->redis);
    ASSERT(state >= SW_START && state < SW_SENTINEL);
    ASSERT(b != NULL);
    ASSERT(b->pos <= b->last);

    /* validate the parsing marker */
    ASSERT(r->pos != NULL);
    ASSERT(r->pos >= b->pos && r->pos <= b->last);
    ASSERT(*(r->pos) == 0x81);

    struct header_t* memcached_header = (struct header_t*) r->pos;

    r->type = MSG_RSP_MC_STORED;
    uint16_t key_length = ntohs(memcached_header->key_length);

    uint32_t body_length = ntohl(memcached_header->body_length);
    r->vlen = body_length - memcached_header->extras_length - key_length;
    p = ((uint8_t*)(memcached_header + 1)) + body_length - 1;

    // TODO handle case where b->last does not contains all the body length
    goto done;

    ASSERT(p == b->last);
    r->pos = p;
    r->state = state;

    if (b->last == b->end && r->token != NULL) {
        if (state <= SW_RUNTO_VAL || state == SW_CRLF || state == SW_ALMOST_DONE) {
            r->state = SW_START;
        }
        r->pos = r->token;
        r->token = NULL;
        r->result = MSG_PARSE_REPAIR;
    } else {
        r->result = MSG_PARSE_AGAIN;
    }

    log_hexdump(LOG_VERB, b->pos, mbuf_length(b), "parsed rsp %"PRIu64" res %d "
                "type %d state %d rpos %d of %d", r->id, r->result, r->type,
                r->state, r->pos - b->pos, b->last - b->pos);
    return;

done:
    ASSERT(r->type > MSG_UNKNOWN && r->type < MSG_SENTINEL);
    r->pos = p + 1;
    ASSERT(r->pos <= b->last);
    r->state = SW_START;
    r->token = NULL;
    r->result = MSG_PARSE_OK;

    log_hexdump(LOG_VERB, b->pos, mbuf_length(b), "parsed rsp %"PRIu64" res %d "
                "type %d state %d rpos %d of %d", r->id, r->result, r->type,
                r->state, r->pos - b->pos, b->last - b->pos);
    return;

error:
    r->result = MSG_PARSE_ERROR;
    r->state = state;
    errno = EINVAL;

    log_hexdump(LOG_INFO, b->pos, mbuf_length(b), "parsed bad rsp %"PRIu64" "
                "res %d type %d state %d", r->id, r->result, r->type,
                r->state);
}

bool
memcache_failure(struct msg *r)
{
    return false;
}

static rstatus_t
memcache_append_key(struct msg *r, uint8_t *key, uint32_t keylen)
{
    struct mbuf *mbuf;
    struct keypos *kpos;

    mbuf = msg_ensure_mbuf(r, keylen + 2);
    if (mbuf == NULL) {
        return NC_ENOMEM;
    }

    kpos = array_push(r->keys);
    if (kpos == NULL) {
        return NC_ENOMEM;
    }

    kpos->start = mbuf->last;
    kpos->end = mbuf->last + keylen;
    mbuf_copy(mbuf, key, keylen);
    r->mlen += keylen;

    mbuf_copy(mbuf, (uint8_t *)" ", 1);
    r->mlen += 1;
    return NC_OK;
}

/*
 * read the comment in proto/nc_redis.c
 */
static rstatus_t
memcache_fragment_retrieval(struct msg *r, uint32_t ncontinuum,
                            struct msg_tqh *frag_msgq,
                            uint32_t key_step)
{
    struct mbuf *mbuf;
    struct msg **sub_msgs;
    uint32_t i;
    rstatus_t status;

    sub_msgs = nc_zalloc(ncontinuum * sizeof(*sub_msgs));
    if (sub_msgs == NULL) {
        return NC_ENOMEM;
    }

    ASSERT(r->frag_seq == NULL);
    r->frag_seq = nc_alloc(array_n(r->keys) * sizeof(*r->frag_seq));
    if (r->frag_seq == NULL) {
        nc_free(sub_msgs);
        return NC_ENOMEM;
    }

    mbuf = STAILQ_FIRST(&r->mhdr);
    mbuf->pos = mbuf->start;

    /*
     * This code is based on the assumption that 'gets ' is located
     * in a contiguous location.
     * This is always true because we have capped our MBUF_MIN_SIZE at 512 and
     * whenever we have multiple messages, we copy the tail message into a new mbuf
     */
//    for (; *(mbuf->pos) != ' ';) {          /* eat get/gets  */
//        mbuf->pos++;
//    }
//    mbuf->pos++;

    r->frag_id = msg_gen_frag_id();
    r->nfrag = 0;
    r->frag_owner = r;

    for (i = 0; i < array_n(r->keys); i++) {        /* for each  key */
        struct msg *sub_msg;
        struct keypos *kpos = array_get(r->keys, i);
        uint32_t idx = msg_backend_idx(r, kpos->start, kpos->end - kpos->start);

        if (sub_msgs[idx] == NULL) {
            sub_msgs[idx] = msg_get(r->owner, r->request, r->redis);
            if (sub_msgs[idx] == NULL) {
                nc_free(sub_msgs);
                return NC_ENOMEM;
            }
        }
        r->frag_seq[i] = sub_msg = sub_msgs[idx];

        sub_msg->narg++;
        status = memcache_append_key(sub_msg, kpos->start, kpos->end - kpos->start);
        if (status != NC_OK) {
            nc_free(sub_msgs);
            return status;
        }
    }

    for (i = 0; i < ncontinuum; i++) {     /* prepend mget header, and forward it */
        struct msg *sub_msg = sub_msgs[i];
        if (sub_msg == NULL) {
            continue;
        }

        /* prepend get/gets */
        if (r->type == MSG_REQ_MC_GET) {
            status = msg_prepend(sub_msg, (uint8_t *)"get ", 4);
        } else if (r->type == MSG_REQ_MC_GETS) {
            status = msg_prepend(sub_msg, (uint8_t *)"gets ", 5);
        }
        if (status != NC_OK) {
            nc_free(sub_msgs);
            return status;
        }

        /* append \r\n */
        status = msg_append(sub_msg, (uint8_t *)CRLF, CRLF_LEN);
        if (status != NC_OK) {
            nc_free(sub_msgs);
            return status;
        }

        sub_msg->type = r->type;
        sub_msg->frag_id = r->frag_id;
        sub_msg->frag_owner = r->frag_owner;

        TAILQ_INSERT_TAIL(frag_msgq, sub_msg, m_tqe);
        r->nfrag++;
    }

    nc_free(sub_msgs);
    return NC_OK;
}

rstatus_t
memcache_fragment(struct msg *r, uint32_t ncontinuum, struct msg_tqh *frag_msgq)
{
    //if (memcache_retrieval(r)) {
    //    return memcache_fragment_retrieval(r, ncontinuum, frag_msgq, 1);
    //}
    return NC_OK;
}

/*
 * Pre-coalesce handler is invoked when the message is a response to
 * the fragmented multi vector request - 'get' or 'gets' and all the
 * responses to the fragmented request vector hasn't been received
 */
void
memcache_pre_coalesce(struct msg *r)
{
    struct msg *pr = r->peer; /* peer request */
    struct mbuf *mbuf;

    ASSERT(!r->request);
    ASSERT(pr->request);

    if (pr->frag_id == 0) {
        /* do nothing, if not a response to a fragmented request */
        return;
    }

    pr->frag_owner->nfrag_done++;
    switch (r->type) {

    case MSG_RSP_MC_VALUE:
    case MSG_RSP_MC_END:

        /*
         * Readjust responses of the fragmented message vector by not
         * including the end marker for all
         */

        ASSERT(r->end != NULL);

        for (;;) {
            mbuf = STAILQ_LAST(&r->mhdr, mbuf, next);
            ASSERT(mbuf != NULL);

            /*
             * We cannot assert that end marker points to the last mbuf
             * Consider a scenario where end marker points to the
             * penultimate mbuf and the last mbuf only contains spaces
             * and CRLF: mhdr -> [...END] -> [\r\n]
             */

            if (r->end >= mbuf->pos && r->end < mbuf->last) {
                /* end marker is within this mbuf */
                r->mlen -= (uint32_t)(mbuf->last - r->end);
                mbuf->last = r->end;
                break;
            }

            /* end marker is not in this mbuf */
            r->mlen -= mbuf_length(mbuf);
            mbuf_remove(&r->mhdr, mbuf);
            mbuf_put(mbuf);
        }

        break;

    default:
        /*
         * Valid responses for a fragmented requests are MSG_RSP_MC_VALUE or,
         * MSG_RSP_MC_END. For an invalid response, we send out SERVER_ERRROR
         * with EINVAL errno
         */
        mbuf = STAILQ_FIRST(&r->mhdr);
        log_hexdump(LOG_ERR, mbuf->pos, mbuf_length(mbuf), "rsp fragment "
                    "with unknown type %d", r->type);
        pr->error = 1;
        pr->err = EINVAL;
        break;
    }
}

/*
 * Copy one response from src to dst and return bytes copied
 */
static rstatus_t
memcache_copy_bulk(struct msg *dst, struct msg *src)
{
    struct mbuf *mbuf, *nbuf;
    uint8_t *p;
    uint32_t len = 0;
    uint32_t bytes = 0;
    uint32_t i = 0;

    for (mbuf = STAILQ_FIRST(&src->mhdr);
         mbuf && mbuf_empty(mbuf);
         mbuf = STAILQ_FIRST(&src->mhdr)) {

        mbuf_remove(&src->mhdr, mbuf);
        mbuf_put(mbuf);
    }

    mbuf = STAILQ_FIRST(&src->mhdr);
    if (mbuf == NULL) {
        return NC_OK;           /* key not exists */
    }
    p = mbuf->pos;

    /*
     * get : VALUE key 0 len\r\nval\r\n
     * gets: VALUE key 0 len cas\r\nval\r\n
     */
    ASSERT(*p == 'V');
    for (i = 0; i < 3; i++) {                 /*  eat 'VALUE key 0 '  */
        for (; *p != ' ';) {
            p++;
        }
        p++;
    }

    len = 0;
    for (; p < mbuf->last && isdigit(*p); p++) {
        len = len * 10 + (uint32_t)(*p - '0');
    }

    for (; p < mbuf->last && ('\r' != *p); p++) { /* eat cas for gets */
        ;
    }

    len += CRLF_LEN * 2;
    len += (p - mbuf->pos);

    bytes = len;

    /* copy len bytes to dst */
    for (; mbuf;) {
        if (mbuf_length(mbuf) <= len) {   /* steal this mbuf from src to dst */
            nbuf = STAILQ_NEXT(mbuf, next);
            mbuf_remove(&src->mhdr, mbuf);
            mbuf_insert(&dst->mhdr, mbuf);
            len -= mbuf_length(mbuf);
            mbuf = nbuf;
        } else {                        /* split it */
            nbuf = mbuf_get();
            if (nbuf == NULL) {
                return NC_ENOMEM;
            }
            mbuf_copy(nbuf, mbuf->pos, len);
            mbuf_insert(&dst->mhdr, nbuf);
            mbuf->pos += len;
            break;
        }
    }

    dst->mlen += bytes;
    src->mlen -= bytes;
    log_debug(LOG_VVERB, "memcache_copy_bulk copy bytes: %d", bytes);
    return NC_OK;
}

/*
 * Post-coalesce handler is invoked when the message is a response to
 * the fragmented multi vector request - 'get' or 'gets' and all the
 * responses to the fragmented request vector has been received and
 * the fragmented request is consider to be done
 */
void
memcache_post_coalesce(struct msg *request)
{
    struct msg *response = request->peer;
    struct msg *sub_msg;
    uint32_t i;
    rstatus_t status;

    ASSERT(!response->request);
    ASSERT(request->request && (request->frag_owner == request));
    if (request->error || request->ferror) {
        response->owner->err = 1;
        return;
    }

    for (i = 0; i < array_n(request->keys); i++) {      /* for each  key */
        sub_msg = request->frag_seq[i]->peer;           /* get it's peer response */
        if (sub_msg == NULL) {
            response->owner->err = 1;
            return;
        }
        status = memcache_copy_bulk(response, sub_msg);
        if (status != NC_OK) {
            response->owner->err = 1;
            return;
        }
    }

    /* append END\r\n */
    status = msg_append(response, (uint8_t *)"END\r\n", 5);
    if (status != NC_OK) {
        response->owner->err = 1;
        return;
    }
}

void
memcache_post_connect(struct context *ctx, struct conn *conn, struct server *server)
{
}

void
memcache_swallow_msg(struct conn *conn, struct msg *pmsg, struct msg *msg)
{
}

rstatus_t
memcache_add_auth(struct context *ctx, struct conn *c_conn, struct conn *s_conn)
{
    NOT_REACHED();
    return NC_OK;
}

rstatus_t
memcache_reply(struct msg *r)
{
    NOT_REACHED();
    return NC_OK;
}

