#include <string.h>
#include "authentication.h"
#include "../shared/parser.h"
#include "../shared/selector.h"
#include "../shared/buffer.h"
#include "../shared/auth.h"
#include "socks5.h"
#include "stdbool.h"
bool keep_feeding_parser = true;
auth_event_type last_event = AUTH_EVENT_ERROR;

// Actions for the authentication parser
static void act_version(struct parser_event *ret, const uint8_t c) {
    ret->type = AUTH_EVENT_VERSION_OK;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_version_error(struct parser_event *ret, const uint8_t c) {
    ret->type = AUTH_EVENT_VERSION_ERROR;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_ulen(struct parser_event *ret, const uint8_t c) {
    ret->type = AUTH_EVENT_ULEN_OK;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_username_byte(struct parser_event *ret, const uint8_t c) {
    ret->type = AUTH_EVENT_USERNAME_BYTE_OK;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_plen(struct parser_event *ret, const uint8_t c) {
    ret->type = AUTH_EVENT_PLEN_OK;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_password_byte(struct parser_event *ret, const uint8_t c) {
    ret->type = AUTH_EVENT_PASSWORD_BYTE_OK;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_error(struct parser_event *ret, const uint8_t c) {
    ret->type = AUTH_EVENT_ERROR;
    ret->data[0] = c;
    ret->n = 1;
}

// State transitions
static const struct parser_state_transition auth_transitions_VERSION[] = {
    { 0x01, AUTH_ULEN, act_version, NULL },
    { ANY, AUTH_ERROR, act_version_error, NULL },
};

static const struct parser_state_transition auth_transitions_ULEN[] = {
    { ANY, AUTH_USERNAME, act_ulen, NULL },
};

static const struct parser_state_transition auth_transitions_USERNAME[] = {
    { ANY, AUTH_PLEN, act_username_byte, NULL },
};

static const struct parser_state_transition auth_transitions_PLEN[] = {
    { ANY, AUTH_PASSWORD, act_plen, NULL },
};

static const struct parser_state_transition auth_transitions_PASSWORD[] = {
    { ANY, AUTH_PASSWORD, act_password_byte, NULL },
};

static const struct parser_state_transition auth_transitions_ERROR[] = {
    { ANY, AUTH_ERROR, act_error, NULL },
};

static const struct parser_state_transition *auth_states[] = {
    auth_transitions_VERSION,
    auth_transitions_ULEN,
    auth_transitions_USERNAME,
    auth_transitions_PLEN,
    auth_transitions_PASSWORD,
    NULL, // AUTH_DONE
    auth_transitions_ERROR
};

static const size_t auth_states_n[] = {
    sizeof(auth_transitions_VERSION)/sizeof(auth_transitions_VERSION[0]),
    sizeof(auth_transitions_ULEN)/sizeof(auth_transitions_ULEN[0]),
    sizeof(auth_transitions_USERNAME)/sizeof(auth_transitions_USERNAME[0]),
    sizeof(auth_transitions_PLEN)/sizeof(auth_transitions_PLEN[0]),
    sizeof(auth_transitions_PASSWORD)/sizeof(auth_transitions_PASSWORD[0]),
    0, // AUTH_DONE
    sizeof(auth_transitions_ERROR)/sizeof(auth_transitions_ERROR[0])
};

static const struct parser_definition auth_parser_def = {
    .states_count = AUTH_STATES_COUNT,
    .states = auth_states,
    .states_n = auth_states_n,
    .start_state = AUTH_VERSION
};

const struct parser_definition * auth_parser_definition(void) {
    return &auth_parser_def;
}

auth_event_type auth_parser_read(client_socks5 * client, struct buffer *buffer) {
    struct parser_event *event;
    size_t count;
    uint8_t *bufptr;

    while ((bufptr = buffer_read_ptr(buffer, &count)) != NULL && count > 0) {
        uint8_t c = bufptr[0];
        buffer_read_adv(buffer, 1);
        if(keep_feeding_parser){
            event = parser_feed(client->parser, c);
        }
        if(event->type == AUTH_EVENT_USERNAME_BYTE_OK || event->type == AUTH_EVENT_PASSWORD_BYTE_OK) {
            keep_feeding_parser = false;
        }
        if (event != NULL || last_event == AUTH_EVENT_USERNAME_BYTE_OK || last_event == AUTH_EVENT_PASSWORD_BYTE_OK) {
            if (event != NULL){
                last_event = event->type;
            }
            switch (last_event) {
                case AUTH_EVENT_VERSION_OK:
                    client->parsing_state.authentication.version = c;
                    break;
                    
                case AUTH_EVENT_VERSION_ERROR:
                    return AUTH_EVENT_VERSION_ERROR;
                    
                case AUTH_EVENT_ULEN_OK:
                    client->parsing_state.authentication.username_len = c;
                    client->parsing_state.authentication.username_bytes_read = 0;
                    if (c == 0) {
                        strcpy(client->auth_info.username, "");
                    }
                    break;
                    
                case AUTH_EVENT_USERNAME_BYTE_OK:
                    if (client->parsing_state.authentication.username_bytes_read < client->parsing_state.authentication.username_len) {
                        client->parsing_state.authentication.temp_username[client->parsing_state.authentication.username_bytes_read] = c;
                        client->parsing_state.authentication.username_bytes_read++;
                        if (client->parsing_state.authentication.username_bytes_read == client->parsing_state.authentication.username_len) {
                            client->parsing_state.authentication.temp_username[client->parsing_state.authentication.username_bytes_read] = '\0';
                            strcpy(client->auth_info.username, client->parsing_state.authentication.temp_username);
                            keep_feeding_parser = true; 
                        }
                    }
                    break;
                    
                case AUTH_EVENT_PLEN_OK:
                    client->parsing_state.authentication.password_len = c;
                    client->parsing_state.authentication.password_bytes_read = 0;
                    if (c == 0) {
                        strcpy(client->auth_info.password, "");
                        memset(&client->parsing_state.authentication, 0, sizeof(client->parsing_state.authentication));
                        return AUTH_EVENT_DONE;
                    }
                    break;
                    
                case AUTH_EVENT_PASSWORD_BYTE_OK:
                    if (client->parsing_state.authentication.password_bytes_read < client->parsing_state.authentication.password_len) {
                        client->parsing_state.authentication.temp_password[client->parsing_state.authentication.password_bytes_read] = c;
                        client->parsing_state.authentication.password_bytes_read++;
                        
                        if (client->parsing_state.authentication.password_bytes_read == client->parsing_state.authentication.password_len) {
                            client->parsing_state.authentication.temp_password[client->parsing_state.authentication.password_bytes_read] = '\0';
                            strcpy(client->auth_info.password, client->parsing_state.authentication.temp_password);
                            keep_feeding_parser = true; 
                            return AUTH_EVENT_DONE;
                        }
                    }
                    break;
                    
                case AUTH_EVENT_ERROR:
                default:
                    return AUTH_EVENT_ERROR;
            }
        }
    }

    return last_event;
}

int generate_auth_response(struct buffer *write_buffer, auth_status status) {
    size_t size;
    uint8_t * buf_ptr = buffer_write_ptr(write_buffer, &size);
    if (size < 2) {
        return -1;
    }
    buf_ptr[0] = AUTHENTICATION_VERSION;
    buf_ptr[1] = status;
    buffer_write_adv(write_buffer, 2);
    return 0; 
}

int authenticate_credentials(const credentials credential) {
    if (strlen(credential.username) > 0 && strlen(credential.password) > 0) {
        return authenticate_user(credential.username, credential.password); 
    }
    return AUTH_STATUS_FAILURE; 
}
