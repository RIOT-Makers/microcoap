#ifndef COAP_H
#define COAP_H 1

/**
 * @file coap.h
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define COAP_VERSION    (0x01)  //!< The CoAP protocol version used

#define COAP_DEFAULT_PORT 5683  //!< The port number used by the CoAP protocol.
#define COAPS_DEFAULT_PORT 5684 //!< The port number used by the CoAPs protocol.

#define COAP_MAX_OPTIONS 8      //!< Maximum number of options in a CoAP packet.
#define COAP_MAX_TOKLEN 8       //!< Maximum token length, not enforced yet

/**
 * The CoAP header definition, see http://tools.ietf.org/html/rfc7252#section-3
 * and for status codes http://tools.ietf.org/html/rfc7252#section-12.1
 */
typedef struct coap_header
{
    uint8_t ver;                //!< version number
    uint8_t t;                  //!< message type
    uint8_t tkl;                //!< token length
    uint8_t code;               //!< status code,
    uint16_t id;                //!< message ID
} coap_header_t;

/**
 * Helper struct to map raw header in send/recv CoAP packets
 */
typedef union {
    uint8_t raw;
    struct {
        uint8_t tkl     : 4;
        uint8_t t       : 2;
        uint8_t ver     : 2;
        uint8_t code;
        uint16_t id;
    } hdr;
} coap_raw_header_t;

/**
 * An immutable buffer container
 */
typedef struct coap_buffer
{
    const uint8_t *p;       //!< byte array that holds some data, immutable
    size_t len;             //!< length of the array in p
} coap_buffer_t;

/**
 * A mutable buffer container
 */
typedef struct coap_rw_buffer
{
    uint8_t *p;             //!< byte array that holds some data, mutable
    size_t len;             //!< length of the array in p
} coap_rw_buffer_t;

/**
 * CoAP option container
 */
typedef struct coap_option
{
    uint8_t num;            //!< option number, http://tools.ietf.org/html/rfc7252#section-5.10
    coap_buffer_t buf;      //!< Option value
} coap_option_t;

/**
 * CoAP packet container, including header, token, options, and payload
 */
typedef struct coap_packet
{
    coap_header_t hdr;      //!< Header of the packet
    coap_buffer_t tok;      //!< Token value, size as specified by hdr.tkl
    uint8_t numopts;        //!< Number of options included in this packet
    coap_option_t opts[COAP_MAX_OPTIONS]; //!< Options of the packet
    coap_buffer_t payload;  //!< Buffer for payload carried by the packet
} coap_packet_t;

/////////////////////////////////////////

/**
 * Definition of CoAP options types, for further information see:
 * COAP    - https://tools.ietf.org/html/rfc7252#section-12.2
 * Block   - https://tools.ietf.org/html/draft-ietf-core-block-20#section-6
 * Observe - https://tools.ietf.org/html/rfc7641#page-9
 */
typedef enum
{
    COAP_OPTION_RESERVED        = 0,
    COAP_OPTION_IF_MATCH        = 1,
    COAP_OPTION_URI_HOST        = 3,
    COAP_OPTION_ETAG            = 4,
    COAP_OPTION_IF_NONE_MATCH   = 5,
    // COAP Observe, https://tools.ietf.org/html/rfc7641#page-9
    COAP_OPTION_OBSERVE         = 6,
    COAP_OPTION_URI_PORT        = 7,
    COAP_OPTION_LOCATION_PATH   = 8,
    COAP_OPTION_URI_PATH        = 11,
    COAP_OPTION_CONTENT_FORMAT  = 12,
    COAP_OPTION_MAX_AGE         = 14,
    COAP_OPTION_URI_QUERY       = 15,
    COAP_OPTION_ACCEPT          = 17,
    COAP_OPTION_LOCATION_QUERY  = 20,
    /* Block-wise transfers in CoAP, options
     * https://tools.ietf.org/html/draft-ietf-core-block-20#section-6
     */
    COAP_OPTION_BLOCK2          = 23,
    COAP_OPTION_BLOCK1          = 27,
    COAP_OPTION_SIZE2           = 28,
    /* END Block-wise transfers in CoAP */
    COAP_OPTION_PROXY_URI       = 35,
    COAP_OPTION_PROXY_SCHEME    = 39,
    COAP_OPTION_SIZE1           = 60,
    COAP_OPTION_NO_RESPONSE     = 258,
} coap_option_num_t;

/**
 * Definition of CoAP methods
 * see http://tools.ietf.org/html/rfc7252#section-12.1.1
 */
typedef enum
{
    COAP_METHOD_GET             = 1,
    COAP_METHOD_POST            = 2,
    COAP_METHOD_PUT             = 3,
    COAP_METHOD_DELETE          = 4,
} coap_method_t;

/**
 * Definition of CoAP message types
 * see http://tools.ietf.org/html/rfc7252#section-12.1.1
 */
typedef enum
{
    COAP_TYPE_CON               = 0,    //!< confirmable message
    COAP_TYPE_NONCON            = 1,    //!< non-confirmable message
    COAP_TYPE_ACK               = 2,    //!< acknowledgement message
    COAP_TYPE_RESET             = 3,    //!< reset message
} coap_msgtype_t;

#define MAKE_RSPCODE(clas, det) ((clas << 5) | (det))   //!< Set CoAP response code
/*
 * Definition of COAP response codes, for further details see following
 * (upcoming) standard documents:
 * https://tools.ietf.org/html/rfc7252#section-5.2
 * https://tools.ietf.org/html/rfc7252#section-12.1.2
 * https://tools.ietf.org/html/draft-ietf-core-block-20#section-6
 */
typedef enum
{
    COAP_RSPCODE_EMPTY                      = MAKE_RSPCODE(0, 0),
    /* Success */
    COAP_RSPCODE_CREATED                    = MAKE_RSPCODE(2, 1),
    COAP_RSPCODE_DELETED                    = MAKE_RSPCODE(2, 2),
    COAP_RSPCODE_VALID                      = MAKE_RSPCODE(2, 3),
    COAP_RSPCODE_CHANGED                    = MAKE_RSPCODE(2, 4),
    COAP_RSPCODE_CONTENT                    = MAKE_RSPCODE(2, 5),
    // https://tools.ietf.org/html/draft-ietf-core-block-20#section-6
    COAP_RSPCODE_CONTINUE                   = MAKE_RSPCODE(2, 31),
    /* Client Errors */
    COAP_RSPCODE_BAD_REQUEST                = MAKE_RSPCODE(4, 0),
    COAP_RSPCODE_UNAUTHORIZED               = MAKE_RSPCODE(4, 1),
    COAP_RSPCODE_BAD_OPTION                 = MAKE_RSPCODE(4, 2),
    COAP_RSPCODE_FORBIDDEN                  = MAKE_RSPCODE(4, 3),
    COAP_RSPCODE_NOT_FOUND                  = MAKE_RSPCODE(4, 4),
    COAP_RSPCODE_METHOD_NOT_ALLOWED         = MAKE_RSPCODE(4, 5),
    COAP_RSPCODE_NOT_ACCEPTABLE             = MAKE_RSPCODE(4, 6),
    // https://tools.ietf.org/html/draft-ietf-core-block-20#section-6
    COAP_RSPCODE_REQUEST_ENTITY_INCOMPLETE  = MAKE_RSPCODE(4,8),
    COAP_RSPCODE_PRECONDITION_FAILED        = MAKE_RSPCODE(4, 12),
    COAP_RSPCODE_REQUEST_ENTITY_TO_LARGE    = MAKE_RSPCODE(4, 13),
    COAP_RSPCODE_UNSUPPORTED_CONTENT_FMT    = MAKE_RSPCODE(4, 15),
    /* Server Errors */
    COAP_RSPCODE_INTERNAL_SERVER_ERROR      = MAKE_RSPCODE(5, 0),
    COAP_RSPCODE_NOT_IMPLEMENTED            = MAKE_RSPCODE(5, 1),
    COAP_RSPCODE_BAD_GATEWAY                = MAKE_RSPCODE(5, 2),
    COAP_RSPCODE_SERVICE_UNAVAILABLE        = MAKE_RSPCODE(5, 3),
    COAP_RSPCODE_GATEWAY_TIMEOUT            = MAKE_RSPCODE(5, 4),
    COAP_RSPCODE_NO_PROXY_SUPPORT           = MAKE_RSPCODE(5, 5),
} coap_responsecode_t;

/**
 * Definition of CoAP content types,
 * see http://tools.ietf.org/html/rfc7252#section-12.3
 */
typedef enum
{
    COAP_CONTENTTYPE_NONE                   = -1, // allow empty payload
    COAP_CONTENTTYPE_TXT_PLAIN              =  0,
    COAP_CONTENTTYPE_APP_LINKFORMAT         = 40,
    COAP_CONTENTTYPE_APP_XML                = 41,
    COAP_CONTENTTYPE_APP_OCTECT_STREAM      = 42,
    COAP_CONTENTTYPE_APP_EXI                = 47,
    COAP_CONTENTTYPE_APP_JSON               = 50,
} coap_content_type_t;

///////////////////////

/**
 * Definition of (internal) states and error codes
 */
typedef enum {
    COAP_SUCCESS                          = 0,
    COAP_RDY,
    COAP_ACK_RECV,
    COAP_ACK_SEND,
    COAP_ACK_WAIT,
    COAP_RSP_RECV,
    COAP_RSP_SEND,
    COAP_RSP_WAIT,
    COAP_REQ_RECV,
    COAP_REQ_SEND,
    COAP_REQ_WAIT,
    COAP_ERR                              = 100,
    COAP_ERR_HEADER_TOO_SHORT,
    COAP_ERR_VERSION_NOT_1,
    COAP_ERR_TOKEN_TOO_SHORT,
    COAP_ERR_OPTION_TOO_SHORT_FOR_HEADER,
    COAP_ERR_OPTION_TOO_SHORT,
    COAP_ERR_OPTION_OVERRUNS_PACKET,
    COAP_ERR_OPTION_TOO_BIG,
    COAP_ERR_OPTION_LEN_INVALID,
    COAP_ERR_BUFFER_TOO_SMALL,
    COAP_ERR_UNSUPPORTED,
    COAP_ERR_OPTION_DELTA_INVALID,
    COAP_ERR_OPTION_NOT_FOUND,
    COAP_ERR_REQUEST_NOT_FOUND,
    COAP_ERR_REQUEST_MSGID_MISMATCH,
    COAP_ERR_REQUEST_TOKEN_MISMATCH,
    COAP_ERR_RESPONSE,
    COAP_ERR_MAX,   // this has to be the last error code
} coap_state_t;


///////////////////////

#ifndef COAP_MAX_PATHITEMS
#define COAP_MAX_PATHITEMS 2  //!< number of path elements
#endif
/**
 * Describes the path elements of a CoAP resource
 */
typedef struct coap_resource_path
{
    int count;                              //!< number of items
    const char *items[COAP_MAX_PATHITEMS];   //!< resource path items
} coap_resource_path_t;

typedef struct coap_resource coap_resource_t;

/**
 * @brief callback function for resource handler
 *
 * @param[in] state State of recursive request handling
 * @param[in] resource Pointer to associated resource handled
 * @param[in] inpkt Pointer to the (incoming) request packet
 * @param[out] pkt Ponter to the (outgoing) response packet
 *
 * @return On success 0, some error code otherwise
 */
typedef int (*coap_resource_handler)(const coap_resource_t *resource,
                                     const coap_packet_t *inpkt,
                                     coap_packet_t *pkt);

/**
 * Describes a distinct resource served by a CoAP entpoint
 */
struct coap_resource
{
    coap_state_t state;                 //!< message handling state
    const coap_method_t method;         //!< method POST, PUT or GET
    const coap_msgtype_t msg_type;      //!< message type CON, NONCON, ACK
    coap_resource_handler handler;      //!< callback function for method
    const coap_resource_path_t *path;   //!< resource path, e.g. foo/bar/
    const uint8_t content_type[2];      //!< content type of response
    const char* attributes;             //!< link target attribute values (http://www.iana.org/assignments/core-parameters/core-parameters.xhtml)
};

/**
 * @brief Set content type
 *
 * Writes uint16_t CoAP content type to a uint8_t[2] array
 * @param[in] ct Content type given as uint16_t
 * @return array with content type
 */
#define COAP_SET_CONTENTTYPE(ct)    {((int16_t)ct & 0xFF00) >> 8, \
                                     ((int16_t)ct & 0x00FF)}

/**
 * @brief Get content type
 *
 * Read uint16_t CoAP content type from a uint8_t[2] array
 * @param[in] buf Pointer to buffer with content type
 * @return content type
 */
#define COAP_GET_CONTENTTYPE(buf)   ((int16_t) ((int16_t)buf[0] << 8) | buf[1])

/**
 * @brief Parse CoAP packet/message from transmission buffer
 *
 * Parses the content of \p buf (i.e. the content of a UDP packet) and
 * writes the values to \p pkt.
 *
 * @param[in] buf The buffer containing the CoAP packet in binary format.
 * @param[in] buflen The lenth of \p buf in bytes.
 * @param[out] pkt The coap_packet_t structure to be filled.
 *
 * @return 0 on success, or the according coap_state_t
 */
coap_state_t coap_parse(const uint8_t *buf,
                        const size_t buflen,
                        coap_packet_t *pkt);

/**
 * @brief Writes CoAP packet/message to transmission buffer
 *
 * Creates a CoAP message from the data in \p pkt and writes the
 * result to \p buf. The actual size of the whole message (which
 * may be smaller than the size of the buffer) will be written to
 * \p buflen. You should use that value (and not \p buflen)
 * when you send the message.
 *
 * @param[in] pkt The packet that is to be converted to binary format.
 * @param[out] buf Byte buffer to which the CoAP packet in binary format will
 * be written to.
 * @param[in,out] buflen Contains the initial size of \p buf, then stores how
 * many bytes have been written to \p buf.
 *
 * @return 0 on success, or COAP_ERR_BUFFER_TOO_SMALL if the size of
 * \p buf is not sufficient, or COAP_ERR_UNSUPPORTED if
 * the token length specified in the header does not match the
 * token length specified in the buffer that actually holds the
 * tokens
 */
coap_state_t coap_build(const coap_packet_t *pkt, uint8_t *buf, size_t *buflen);

/**
 * @brief Create CoAP acknowledgement
 *
 * Creates an ACK packet for the given message ID, and stores it in the
 * coap_packet_t structure pointed to by \p pkt.
 *
 * @param[in] msgid The message ID.
 * @param[in] tok Pointer to the token used.
 * @param[out] pkt Pointer to the coap_packet_t structure to be filled
 *
 * @return Always returns 0.
 */
coap_state_t coap_make_ack(const coap_packet_t *inpkt, coap_packet_t *pkt);

/**
 *
 */
coap_state_t coap_make_request(const uint16_t msgid, const coap_buffer_t* tok,
                               const coap_resource_t *resource,
                               const uint8_t *content, const size_t content_len,
                               coap_packet_t *pkt);

/**
 * @brief Create a CoAP response packet
 *
 * Creates a response-only packet for a request, and stores it in
 * the coap_packet_t structure pointed to by \p pkt.
 *
 * @param[in] msgid The message ID.
 * @param[in] tok Pointer to the token used.
 * @param[in] msgtype The message type (CON, NON, ACK).
 * @param[in] rspcode The response code.
 * @param[in] content_type The content type (i.e. what does the payload contain)
 * @param[in] content The response payload.
 * @param[in] content_len Length of \p content in bytes.
 * @param[out] pkt Pointer to the coap_packet_t that will be filled.
 *
 * @return 0 on success, or COAP_ERR_BUFFER_TOO_SMALL if the length of the
 * buffer pointed to by scratch is smaller than 2.
 */
coap_state_t coap_make_response(const uint16_t msgid,
                                const coap_buffer_t* tok,
                                const coap_msgtype_t msgtype,
                                const coap_responsecode_t rspcode,
                                const uint8_t *content_type,
                                const uint8_t *content,
                                const size_t content_len,
                                coap_packet_t *pkt);

/**
 * @brief Handle incoming CoAP request
 *
 * Handles the CoAP request in \p inpkt, and creates a response packet which is
 * stored in \p pkt.
 *
 * @param[in/out] resources Pointer to the coap_resource_t array of all resources.
 * @param[in] inpkt Pointer to the coap_packet_t structure containing the
 * request.
 * @param[out] pkt Pointer to the coap_packet_t structure that will be
 * filled, then containing the response.
 *
 * @return 0 on success, or a reasonable error code on failure.
 */
coap_state_t coap_handle_request(coap_resource_t *resources,
                                 const coap_packet_t *inpkt,
                                 coap_packet_t *pkt);

coap_state_t coap_handle_response(coap_resource_t *resources,
                                  const coap_packet_t *reqpkt,
                                  coap_packet_t *rsppkt);

/**
 * @brief Create link format of resources
 *
 * @param[in] resources Array describing all available coap_resource_t
 * @param[out] buf Char buffer to which resource link format will be written to.
 * @param[in,out] buflen Contains the initial size of \p buf, then stores how
 * many bytes have been written to \p buf.
 *
 * @return 0 on success, or COAP_ERR_BUFFER_TOO_SMALL if buflen is exceeded.
 */
coap_state_t coap_make_link_format(const coap_resource_t *resources,
                                   char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif
