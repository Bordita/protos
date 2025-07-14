#ifndef __authentication_socks_h
#define __authentication_socks_h

#include <stdint.h>
#include "../../shared/includes/parser.h"
#include "../../shared/includes/buffer.h"
#include "../../shared/includes/selector.h"
#include "socks5.h"

static const uint8_t AUTHENTICATION_VERSION = 0x01;



typedef enum {
    AUTH_EVENT_VERSION_OK = 0,
    AUTH_EVENT_VERSION_ERROR,
    AUTH_EVENT_ULEN_OK,
    AUTH_EVENT_USERNAME_BYTE_OK,
    AUTH_EVENT_USERNAME_DONE,
    AUTH_EVENT_PLEN_OK,
    AUTH_EVENT_PASSWORD_BYTE_OK,
    AUTH_EVENT_PASSWORD_DONE,
    AUTH_EVENT_DONE,
    AUTH_EVENT_ERROR
} auth_event_type;

typedef enum {
    AUTH_VERSION = 0,
    AUTH_ULEN,
    AUTH_USERNAME,
    AUTH_PLEN,
    AUTH_PASSWORD,
    AUTH_DONE,
    AUTH_ERROR,
    AUTH_STATES_COUNT
} auth_state;

typedef enum {
    AUTH_STATUS_SUCCESS = 0x00,
    AUTH_STATUS_FAILURE = 0x01,
} auth_status;

auth_event_type auth_parser_read(client_socks5 * client, struct buffer *buffer);
const struct parser_definition * auth_parser_definition(void);
int generate_auth_response(struct buffer *write_buffer, auth_status status);
int authenticate_credentials(const credentials credential);

#endif
