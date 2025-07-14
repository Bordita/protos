#ifndef __request_socks_h
#define __request_socks_h

#include <stdint.h>
#include "../../shared/includes/parser.h"
#include "../../shared/includes/buffer.h"
#include "../../shared/includes/selector.h"
#include "socks5.h"



// Events for the request parser
typedef enum {
    REQUEST_EVENT_VERSION_OK = 0,
    REQUEST_EVENT_VERSION_ERROR,
    REQUEST_EVENT_CMD_OK,
    REQUEST_EVENT_CMD_ERROR,
    REQUEST_EVENT_RSV_OK,
    REQUEST_EVENT_ATYP_OK,
    REQUEST_EVENT_ATYP_ERROR,
    REQUEST_EVENT_ADDR_PORT_BYTE_OK,
    REQUEST_EVENT_ADDR_PORT_DONE,
    REQUEST_EVENT_DONE,
    REQUEST_EVENT_ERROR
} request_event_type;

typedef enum {
    REQUEST_VERSION = 0,
    REQUEST_CMD,
    REQUEST_RSV,
    REQUEST_ATYP,
    REQUEST_ADDR_PORT,
    REQUEST_DONE,
    REQUEST_ERROR,
    REQUEST_STATES_COUNT
} request_state;


// Reply Codes
typedef enum {
    REP_SUCCEEDED = 0x00,
    REP_GENERAL_FAILURE = 0x01,
    REP_CONNECTION_NOT_ALLOWED = 0x02,
    REP_NETWORK_UNREACHABLE = 0x03,
    REP_HOST_UNREACHABLE = 0x04,
    REP_CONNECTION_REFUSED = 0x05,
    REP_TTL_EXPIRED = 0x06,
    REP_COMMAND_NOT_SUPPORTED = 0x07,
    REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08
} socks5_reply;


request_event_type request_parser_read(client_socks5 * client, struct buffer *buffer);
const struct parser_definition * request_parser_definition(void);
int generate_request_response(struct buffer *write_buffer, socks5_reply reply, socks5_atyp atyp, const char *bind_addr, uint16_t bind_port);

#endif
