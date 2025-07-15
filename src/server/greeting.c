
#include <string.h>
#include "includes/greeting.h"
#include "../shared/includes/parser.h"
#include "../shared/includes/selector.h"
#include "../shared/includes/buffer.h"
#include "includes/socks5.h"
#include "../shared/includes/auth.h"

static void act_version(struct parser_event *ret, const uint8_t c) {
    ret->type = GREETING_EVENT_VERSION_OK;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_version_error(struct parser_event *ret, const uint8_t c) {
    ret->type = GREETING_EVENT_VERSION_ERROR;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_nmethods(struct parser_event *ret, const uint8_t c) {
    ret->type = GREETING_EVENT_NMETHODS_OK;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_method(struct parser_event *ret, const uint8_t c) {
    ret->type = GREETING_EVENT_METHOD_OK;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_error(struct parser_event *ret, const uint8_t c) {
    ret->type = GREETING_EVENT_ERROR;
    ret->data[0] = c;
    ret->n = 1;
}


static const struct parser_state_transition greeting_transitions_VERSION[] = {
    { 0x05, GREETING_NMETHODS, act_version, NULL },
    { ANY, GREETING_ERROR, act_version_error, NULL },
};

static const struct parser_state_transition greeting_transitions_NMETHODS[] = {
    { ANY, GREETING_METHODS, act_nmethods, NULL },
};

static const struct parser_state_transition greeting_transitions_METHODS[] = {
    { ANY, GREETING_METHODS, act_method, NULL },
};

static const struct parser_state_transition greeting_transitions_ERROR[] = {
    { ANY, GREETING_ERROR, act_error, NULL },
};

static const struct parser_state_transition *greeting_states[] = {
    greeting_transitions_VERSION,
    greeting_transitions_NMETHODS,
    greeting_transitions_METHODS,
    NULL, 
    greeting_transitions_ERROR
};

static const size_t greeting_states_n[] = {
    sizeof(greeting_transitions_VERSION)/sizeof(greeting_transitions_VERSION[0]),
    sizeof(greeting_transitions_NMETHODS)/sizeof(greeting_transitions_NMETHODS[0]),
    sizeof(greeting_transitions_METHODS)/sizeof(greeting_transitions_METHODS[0]),
    0,
    sizeof(greeting_transitions_ERROR)/sizeof(greeting_transitions_ERROR[0])
};

static const struct parser_definition greeting_parser_def = {
    .states_count = GREETING_STATES_COUNT,
    .states = greeting_states,
    .states_n = greeting_states_n,
    .start_state = GREETING_VERSION
};

const struct parser_definition * greeting_parser_definition(void) {
    return &greeting_parser_def;
}

greeting_event_type parser_read(client_socks5 * client, struct buffer *buffer) {
    const struct parser_event *event;
    greeting_event_type last_event = GREETING_EVENT_ERROR;
     while (buffer_can_read(buffer)) {
        const uint8_t byte = buffer_read(buffer);

        event = parser_feed(client->parser, byte);
        if (event != NULL) {
            last_event = event->type;
            switch (event->type) {
                case GREETING_EVENT_VERSION_OK:
                    break;
                    
                case GREETING_EVENT_VERSION_ERROR:
                    return GREETING_EVENT_VERSION_ERROR;
                    
                case GREETING_EVENT_NMETHODS_OK:
                    client->parsing_state.greeting.expected_methods = byte;
                    client->parsing_state.greeting.methods_read = 0;
                    break;
                    
                case GREETING_EVENT_METHOD_OK:
                    if (client->parsing_state.greeting.methods_read < client->parsing_state.greeting.expected_methods) {
                        client->parsing_state.greeting.received_methods[client->parsing_state.greeting.methods_read] = byte;
                        client->parsing_state.greeting.methods_read++;
                        
                        
                        if (client->parsing_state.greeting.methods_read == client->parsing_state.greeting.expected_methods) {
                            client->selected_method = METHOD_NO_ACCEPTABLE_METHODS;
                            
                            for (int i = 0; i < client->parsing_state.greeting.methods_read; i++) {
                                if (client->parsing_state.greeting.received_methods[i] == METHOD_NO_AUTHENTICATION_REQUIRED && !authentication_enabled()) { 
                                    client->selected_method = METHOD_NO_AUTHENTICATION_REQUIRED;
                                } else if (client->parsing_state.greeting.received_methods[i] == METHOD_USERNAME_PASSWORD) { 
                                    client->selected_method = METHOD_USERNAME_PASSWORD;
                                    break;
                                }
                            }
                            return GREETING_EVENT_DONE;
                        }
                    }
                    break;
                    
                case GREETING_EVENT_ERROR:
                default:
                    return GREETING_EVENT_ERROR;
            }
        }
    }

    return last_event;
}

int generate_connection_response(buffer *write_buffer, authentication_method selected_method) {
    size_t size;
    uint8_t * buf_ptr = buffer_write_ptr(write_buffer, &size);
    if (size < 2) {
        return -1;
    }
    buf_ptr[0] = SOCKS_VERSION;
    buf_ptr[1] = selected_method;
    buffer_write_adv(write_buffer, 2);
    return 0;
}
