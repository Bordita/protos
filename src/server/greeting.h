#ifndef __greeting_socks_h
#define __greeting_socks_h

#include <stdint.h>
#include "../shared/includes/parser.h"
#include "../shared/includes/buffer.h"
#include "../shared/includes/selector.h"
#include "socks5.h"



// Events for the greeting parser
typedef enum {
    GREETING_EVENT_VERSION_OK = 0,
    GREETING_EVENT_VERSION_ERROR,
    GREETING_EVENT_NMETHODS_OK,
    GREETING_EVENT_METHOD_OK,
    GREETING_EVENT_DONE,
    GREETING_EVENT_ERROR
}greeting_event_type;

typedef enum {
    GREETING_VERSION = 0,
    GREETING_NMETHODS,
    GREETING_METHODS,
    GREETING_DONE,
    GREETING_ERROR,
    GREETING_STATES_COUNT
}greeting_state;


greeting_event_type parser_read(client_socks5 * client, struct buffer *buffer);
const struct parser_definition * greeting_parser_definition(void);
int generate_connection_response(buffer *write_buffer, authentication_method selected_method);
#endif
