#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>

#include "coap.h"

/* --- PRIVATE -------------------------------------------------------------- */
static const coap_option_t *_find_options(const coap_packet_t *pkt,
                                          const coap_option_num_t num,
                                          uint8_t *count);
static void _option_decode(const uint32_t value, uint8_t *delta);

/*
 * options are always stored consecutively,
 * so can return a block with same option num
 */
static const coap_option_t *_find_options(const coap_packet_t *pkt,
                                          const coap_option_num_t num,
                                          uint8_t *count)
{
    const coap_option_t * first = NULL;
    /* loop through packet opts */
    *count = 0;
    for (size_t i = 0; i < pkt->numopts; ++i) {
        if (pkt->opts[i].num == num) {
            if (!first) {
                first = &pkt->opts[i];
            }
            (*count)++;
        }
        /* options are ordered by num, skip if greater */
        else if (pkt->opts[i].num > num) {
            break;
        }
        /* single block for same option num, skip on first match */
        else if (first) {
            break;
        }
    }
    return first;
}

/* https://tools.ietf.org/html/rfc7252#section-3.1 */
static void _option_decode(const uint32_t value, uint8_t *delta)
{
    if (value < 13) {
        *delta = (0xFF & value);
    }
    else if (value <= 0xFF+13) {
        *delta = 13;
    }
    else if (value <= 0xFFFF+269) {
        *delta = 14;
    }
}



// https://tools.ietf.org/html/rfc7252#section-5.10.3
// https://tools.ietf.org/html/rfc7252#section-5.10.4
bool _handle_specific_content_format(coap_resource_t *rs, const coap_option_t *opt, 
    const coap_packet_t *inpkt, coap_packet_t *pkt)
{
    // TODO: make this debug-only
    /*
    printf("Reaching CONTENT-FORMAT handler: %x.%x == %x.%x / len %d\r\n", 
        opt->buf.p[0], opt->buf.p[1],
        rs->content_type[0], rs->content_type[1],
        opt->buf.len); */

    if(opt->buf.p[0] == rs->content_type[1])
    {
        if(opt->buf.len == 2)
            if(opt->buf.p[1] != rs->content_type[0]) return false;
            
        rs->state = rs->handler(rs, inpkt, pkt);
        return true;
    }
    
    return false;
}



/* --- PUBLIC --------------------------------------------------------------- */
coap_state_t coap_build(const coap_packet_t *pkt, uint8_t *buf, size_t *buflen)
{
    // build header
    if (*buflen < (sizeof(coap_raw_header_t) + pkt->hdr.tkl)) {
        return COAP_ERR_BUFFER_TOO_SMALL;
    }
    coap_raw_header_t *r = (coap_raw_header_t *)buf;
    r->hdr.ver = pkt->hdr.ver;
    r->hdr.t = pkt->hdr.t;
    r->hdr.tkl = pkt->hdr.tkl;
    r->hdr.code = pkt->hdr.code;
    r->hdr.id = htons(pkt->hdr.id);
    // inject token
    uint8_t *p = buf + sizeof(coap_raw_header_t);
    if ((pkt->hdr.tkl > 0) && (pkt->hdr.tkl != pkt->tok.len)) {
        return COAP_ERR_UNSUPPORTED;
    }
    if (pkt->hdr.tkl > 0) {
        memcpy(p, pkt->tok.p, pkt->hdr.tkl);
    }
    p += pkt->hdr.tkl;
    // inject options, http://tools.ietf.org/html/rfc7252#section-3.1
    uint16_t running_delta = 0;
    for (size_t i = 0; i < pkt->numopts; ++i) {
        if (((size_t)(p - buf)) > *buflen) {
            return COAP_ERR_BUFFER_TOO_SMALL;
        }
        uint32_t optDelta = pkt->opts[i].num - running_delta;
        uint8_t delta = 0;
        _option_decode(optDelta, &delta);
        uint8_t len = 0;
        _option_decode((uint32_t)pkt->opts[i].buf.len, &len);

        *p++ = (0xFF & (delta << 4 | len));
        if (delta == 13) {
            *p++ = (optDelta - 13);
        }
        else if (delta == 14) {
            *p++ = ((optDelta-269) >> 8);
            *p++ = (0xFF & (optDelta-269));
        }
        if (len == 13) {
            *p++ = (pkt->opts[i].buf.len - 13);
        }
        else if (len == 14) {
            *p++ = (pkt->opts[i].buf.len >> 8);
            *p++ = (0xFF & (pkt->opts[i].buf.len-269));
        }

        memcpy(p, pkt->opts[i].buf.p, pkt->opts[i].buf.len);
        p += pkt->opts[i].buf.len;
        running_delta = pkt->opts[i].num;
    }
    // calc number of bytes used by options
    size_t opts_len = (p - buf) - sizeof(coap_raw_header_t);
    if (pkt->payload.len > 0) {
        if (*buflen < sizeof(coap_raw_header_t) + 1 + pkt->payload.len + opts_len) {
            return COAP_ERR_BUFFER_TOO_SMALL;
        }
        buf[sizeof(coap_raw_header_t) + opts_len] = 0xFF;  // payload marker
        memcpy(buf + sizeof(coap_raw_header_t) + opts_len + 1,
               pkt->payload.p, pkt->payload.len);
        *buflen = sizeof(coap_raw_header_t) + opts_len + 1 + pkt->payload.len;
    }
    else {
        *buflen = opts_len + sizeof(coap_raw_header_t);
    }
    return COAP_SUCCESS;
}

coap_state_t coap_make_request(const uint16_t msgid,
                               const coap_buffer_t* tok,
                               const coap_resource_t *resource,
                               const uint8_t *content,
                               const size_t content_len,
                               coap_packet_t *pkt)
{
    const coap_resource_path_t *path = resource->path;
    const coap_msgtype_t msg_type = resource->msg_type;
    // check if path elements + content type fit into option array
    if ((path->count + 1) > COAP_MAX_OPTIONS)
        return COAP_ERR_BUFFER_TOO_SMALL;
    // init request header
    pkt->hdr.ver = COAP_VERSION;
    pkt->hdr.t = msg_type;
    pkt->hdr.tkl = 0;
    pkt->hdr.code = resource->method;
    pkt->hdr.id = msgid;
    pkt->numopts = 0;
    // set token
    if (tok) {
        pkt->hdr.tkl = tok->len;
        pkt->tok = *tok;
    }
    /*
     * NOTE: coap options MUST be in ascending order, i.e.,
     *       COAP_OPTION_URI_PATH (11) < COAP_OPTION_CONTENT_FORMAT (12)
     */
    // copy path to options, first
    int i;
    for (i=0; i < path->count; ++i) {
        pkt->opts[i].num = COAP_OPTION_URI_PATH;
        pkt->opts[i].buf.p = (const uint8_t *) path->items[i];
        pkt->opts[i].buf.len = strlen(path->items[i]);
        pkt->numopts++;
    }
    // set content type, if present afterwards
    if (COAP_GET_CONTENTTYPE(resource->content_type) != COAP_CONTENTTYPE_NONE) {
        pkt->opts[i].num = COAP_OPTION_CONTENT_FORMAT;
        pkt->opts[i].buf.p = resource->content_type;
        pkt->opts[i].buf.len = 2;
        pkt->numopts++;
    }
    // attach payload
    pkt->payload.p = content;
    pkt->payload.len = content_len;
    return COAP_REQ_SEND;
}

coap_state_t coap_make_ack(const coap_packet_t *inpkt, coap_packet_t *pkt)
{
    printf("coap_make_ack\n");
    return coap_make_response(inpkt->hdr.id, &inpkt->tok,
                              COAP_TYPE_ACK, COAP_RSPCODE_EMPTY,
                              NULL, NULL, 0, pkt);
}

coap_state_t coap_make_response(const uint16_t msgid,
                                const coap_buffer_t* tok,
                                const coap_msgtype_t msgtype,
                                const coap_responsecode_t rspcode,
                                const uint8_t *content_type,
                                const uint8_t *content,
                                const size_t content_len,
                                coap_packet_t *pkt)
{
    pkt->hdr.ver = COAP_VERSION;
    pkt->hdr.t = msgtype;
    pkt->hdr.tkl = 0;
    pkt->hdr.code = rspcode;
    pkt->hdr.id = msgid;
    pkt->numopts = 0;
    // need token in response
    if (tok) {
        pkt->hdr.tkl = tok->len;
        pkt->tok = *tok;
    }
    if (content_type) {
        pkt->numopts = 1;
        // safe because 1 < COAP_MAX_OPTIONS
        pkt->opts[0].num = COAP_OPTION_CONTENT_FORMAT;
        pkt->opts[0].buf.p = content_type;
        pkt->opts[0].buf.len = 2;
    }
    pkt->payload.p = content;
    pkt->payload.len = content_len;
    if ((msgtype == COAP_TYPE_ACK) && (rspcode == COAP_RSPCODE_EMPTY))
        return COAP_ACK_SEND;
    return COAP_RSP_SEND;
}


coap_state_t coap_handle_request(coap_resource_t *resources,
                                 const coap_packet_t *inpkt,
                                 coap_packet_t *pkt)
{
    uint8_t count, count_accept, count_cf;
    coap_responsecode_t rspcode = COAP_RSPCODE_NOT_IMPLEMENTED;
    const coap_option_t *opt = _find_options(inpkt, COAP_OPTION_URI_PATH, &count);
    // https://tools.ietf.org/html/rfc7252#section-5.10.4
    const coap_option_t *opt_accept;
    // https://tools.ietf.org/html/rfc7252#section-5.10.3
    // Content-Format mode is like Accept, but the difference is this:
    // Accept *demands* a particular content-type, while Content-Format merely asks
    const coap_option_t *opt_cf;
    coap_resource_t *rs_bestfit = NULL; // for Content-Format mode

    // Not super efficient to do many distinct _find_options, 
    // but we'll optimize another time :)
    opt_accept = _find_options(inpkt, COAP_OPTION_ACCEPT, &count_accept);
    opt_cf = _find_options(inpkt, COAP_OPTION_CONTENT_FORMAT, &count_cf);

    // find handler for requested resource
    for (coap_resource_t *rs = resources; rs->handler && opt; ++rs) {
        if ((rs->method == inpkt->hdr.code) && (count == rs->path->count)){
            int i;
            for (i = 0; i < count; ++i) {
                if (opt[i].buf.len != strlen(rs->path->items[i])) {
                    break;
                }
                if (memcmp(rs->path->items[i], opt[i].buf.p, opt[i].buf.len)) {
                    break;
                }
            }
            if (i == count) { // matching resource found
                if ((inpkt->hdr.t == COAP_TYPE_CON) && (rs->msg_type != COAP_TYPE_ACK) && (rs->state != COAP_ACK_SEND)) { // no piggyback
                    rs->state = coap_make_ack(inpkt, pkt);
                }
                else {
                    if(opt_accept) // Accept activated, particular Content-Format requested
                    {
                        if(_handle_specific_content_format(rs, opt_accept, inpkt, pkt))
                            return rs->state;

                        // default the failure code now to NOT ACCEPTABLE, and fall thru to next
                        // resource.  If no resources can pick this up, a not acceptable will then
                        // be returned
                        rspcode = COAP_RSPCODE_NOT_ACCEPTABLE;
                        continue;
                    }
                    else if(opt_cf) // Content-Format mode activated
                    {
                        rs_bestfit = rs;
                        if(_handle_specific_content_format(rs, opt_cf, inpkt, pkt))
                            return rs->state;
                            
                        continue;
                        // Keep looking, default will route through rs_bestfit
                    }
                    else
                        rs->state = rs->handler(rs, inpkt, pkt);
                }
                return rs->state;
            }
            rspcode = COAP_RSPCODE_NOT_FOUND;
        }
        else {
            rspcode = COAP_RSPCODE_METHOD_NOT_ALLOWED;
        }
    }
    
    // Content-Format mode 
    if(opt_cf && rs_bestfit)
    {
        rs_bestfit->state = rs_bestfit->handler(rs_bestfit, inpkt, pkt);
        return rs_bestfit->state;
    }
    return coap_make_response(inpkt->hdr.id, &inpkt->tok,
                              COAP_TYPE_ACK, rspcode,
                              NULL, NULL, 0, pkt);
}

coap_state_t coap_handle_response(coap_resource_t *resources,
                                  const coap_packet_t *reqpkt,
                                  coap_packet_t *rsppkt)
{
    if (reqpkt->hdr.id  != rsppkt->hdr.id )
        return COAP_ERR_REQUEST_MSGID_MISMATCH;
    if (reqpkt->hdr.tkl != rsppkt->hdr.tkl)
        return COAP_ERR_REQUEST_TOKEN_MISMATCH;
    else if (memcmp(reqpkt->tok.p, rsppkt->tok.p, reqpkt->tok.len) != 0)
        return COAP_ERR_REQUEST_TOKEN_MISMATCH;
    if (rsppkt->hdr.code >= COAP_RSPCODE_BAD_REQUEST)
        return COAP_ERR_RESPONSE;
    uint8_t count;
    const coap_option_t *opt = _find_options(reqpkt, COAP_OPTION_URI_PATH, &count);
    // find handler for requested resource
    for (coap_resource_t *rs = resources; rs->handler && opt; ++rs) {
        if (count == rs->path->count) {
            int i;
            for (i = 0; i < count; ++i) {
                if (opt[i].buf.len != strlen(rs->path->items[i])) {
                    break;
                }
                if (memcmp(rs->path->items[i], opt[i].buf.p, opt[i].buf.len)) {
                    break;
                }
            }
            if (i == count) { // matching resource found
                return rs->handler(rs, reqpkt, rsppkt);
            }
        }
    }
    return COAP_ERR_REQUEST_NOT_FOUND;
}

coap_state_t coap_make_link_format(const coap_resource_t *resources,
                                   char *buf, size_t buflen)
{
    if (buflen < 4) { // <>;
        return COAP_ERR_BUFFER_TOO_SMALL;
    }
    memset(buf,0,buflen);
    // loop over resources
    int len = buflen - 1;
    const coap_resource_t *rs_prev = NULL;
    for (const coap_resource_t *rs = resources; rs->handler; (rs_prev = rs, ++rs)) {
        if (0 > len)
            return COAP_ERR_BUFFER_TOO_SMALL;
        
        // skip if missing content type
        if (COAP_CONTENTTYPE_NONE == COAP_GET_CONTENTTYPE(rs->content_type))
            continue;

        // if we're servicing the exact same path on this resource as the
        // previous resource
        if(rs_prev != NULL && rs_prev->path == rs->path)
        {
            // shouldn't this be uint16_t?
            int16_t content_type = COAP_GET_CONTENTTYPE(rs->content_type);
            
            // *AND* we haven't already reported this particular content type
            if(content_type != COAP_GET_CONTENTTYPE(rs_prev->content_type))
            // then we expect this is a different content type handler,
            // and append according to the end of https://tools.ietf.org/html/draft-ietf-core-coap-01#section-6.1
            // superseded by https://tools.ietf.org/html/rfc7252#section-7.2.1, so we space delimit
            // also: sprintf big and sloppy, but powerful and cross platform.
                len -= sprintf(buf + (buflen - len - 1), " %d", content_type);
                           
            continue;
        }
        // comma separated list
        if (0 < strlen(buf)) {
            strncat(buf, ",", len);
            len--;
        }
        // insert < at path beginning
        strncat(buf, "<", len);
        len--;
        // insert path by elements
        for (int i = 0; i < rs->path->count; i++) {
            strncat(buf, "/", len);
            len--;

            strncat(buf, rs->path->items[i], len);
            len -= strlen(rs->path->items[i]);
        }
        // insert >; after path
        strncat(buf, ">;", len);
        if(rs->attributes != NULL)
        {
            // Be sure to have a trailing ; !
            // TODO: do a debug-only runtime check for above
            strncat(buf, rs->attributes, len);
            len -= strlen(rs->attributes);
        }
        len -= 2;
        // append content type
        len -= sprintf(buf + (buflen - len - 1), "ct=%d",
                       COAP_GET_CONTENTTYPE(rs->content_type));
    }
    return COAP_SUCCESS;
}
