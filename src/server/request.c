#include <string.h>
#include <arpa/inet.h>
#include "includes/request.h"
#include "../shared/includes/parser.h"
#include "../shared/includes/selector.h"
#include "../shared/includes/buffer.h"
#include "includes/socks5.h"


// Actions for the request parser 
static void act_version(struct parser_event *ret, const uint8_t c) {
    ret->type = REQUEST_EVENT_VERSION_OK;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_version_error(struct parser_event *ret, const uint8_t c) {
    ret->type = REQUEST_EVENT_VERSION_ERROR;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_cmd(struct parser_event *ret, const uint8_t c) {
    if (c == CMD_CONNECT) {
        ret->type = REQUEST_EVENT_CMD_OK;
    } else {
        ret->type = REQUEST_EVENT_CMD_ERROR;
    }
    ret->data[0] = c;
    ret->n = 1;
}

static void act_rsv(struct parser_event *ret, const uint8_t c) {
    ret->type = REQUEST_EVENT_RSV_OK;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_atyp(struct parser_event *ret, const uint8_t c) {
    if (c == ATYP_IPV4 || c == ATYP_DOMAINNAME || c == ATYP_IPV6) {
        ret->type = REQUEST_EVENT_ATYP_OK;
    } else {
        ret->type = REQUEST_EVENT_ATYP_ERROR;
    }
    ret->data[0] = c;
    ret->n = 1;
}

static void act_addr_byte(struct parser_event *ret, const uint8_t c) {
    ret->type = REQUEST_EVENT_ADDR_PORT_BYTE_OK;
    ret->data[0] = c;
    ret->n = 1;
}

static void act_error(struct parser_event *ret, const uint8_t c) {
    ret->type = REQUEST_EVENT_ERROR;
    ret->data[0] = c;
    ret->n = 1;
}

// State transitions
static const struct parser_state_transition request_transitions_VERSION[] = {
    { 0x05, REQUEST_CMD, act_version, NULL },
    { ANY, REQUEST_ERROR, act_version_error, NULL },
};

static const struct parser_state_transition request_transitions_CMD[] = {
    { CMD_CONNECT, REQUEST_RSV, act_cmd, NULL },
    { ANY, REQUEST_ERROR, act_cmd, NULL },
};

static const struct parser_state_transition request_transitions_RSV[] = {
    { 0x00, REQUEST_ATYP, act_rsv, NULL },
    { ANY, REQUEST_ERROR, act_error, NULL },
};

static const struct parser_state_transition request_transitions_ATYP[] = {
    { ATYP_IPV4, REQUEST_ADDR_PORT, act_atyp, NULL },
    { ATYP_DOMAINNAME, REQUEST_ADDR_PORT, act_atyp, NULL },
    { ATYP_IPV6, REQUEST_ADDR_PORT, act_atyp, NULL },
    { ANY, REQUEST_ERROR, act_atyp, NULL },
};

static const struct parser_state_transition request_transitions_ADDR_PORT[] = {
    { ANY, REQUEST_ADDR_PORT, act_addr_byte, NULL },
};


static const struct parser_state_transition request_transitions_ERROR[] = {
    { ANY, REQUEST_ERROR, act_error, NULL },
};

static const struct parser_state_transition *request_states[] = {
    request_transitions_VERSION,
    request_transitions_CMD,
    request_transitions_RSV,
    request_transitions_ATYP,
    request_transitions_ADDR_PORT,
    NULL, // REQUEST_DONE
    request_transitions_ERROR
};

static const size_t request_states_n[] = {
    sizeof(request_transitions_VERSION)/sizeof(request_transitions_VERSION[0]),
    sizeof(request_transitions_CMD)/sizeof(request_transitions_CMD[0]),
    sizeof(request_transitions_RSV)/sizeof(request_transitions_RSV[0]),
    sizeof(request_transitions_ATYP)/sizeof(request_transitions_ATYP[0]),
    sizeof(request_transitions_ADDR_PORT)/sizeof(request_transitions_ADDR_PORT[0]),
    0, // REQUEST_DONE
    sizeof(request_transitions_ERROR)/sizeof(request_transitions_ERROR[0])
};

static const struct parser_definition request_parser_def = {
    .states_count = REQUEST_STATES_COUNT,
    .states = request_states,
    .states_n = request_states_n,
    .start_state = REQUEST_VERSION
};

const struct parser_definition * request_parser_definition(void) {
    return &request_parser_def;
}

request_event_type request_parser_read(client_socks5 * client, struct buffer *buffer) {
    const struct parser_event *event;
    size_t count;
    uint8_t *bufptr;
    request_event_type last_event = REQUEST_EVENT_ERROR;

    while ((bufptr = buffer_read_ptr(buffer, &count)) != NULL && count > 0) {
        uint8_t c = bufptr[0];
        buffer_read_adv(buffer, 1);

        event = parser_feed(client->parser, c);
        if (event != NULL) {
            last_event = event->type;

            switch (event->type) {
                case REQUEST_EVENT_VERSION_OK:
                    client->parsing_state.request.version = c;
                    break;
                    
                case REQUEST_EVENT_VERSION_ERROR:
                    return REQUEST_EVENT_VERSION_ERROR;
                    
                case REQUEST_EVENT_CMD_OK:
                    client->parsing_state.request.cmd = (socks5_cmd)c;
                    client->request_info.cmd = (socks5_cmd)c;
                    break;
                    
                case REQUEST_EVENT_CMD_ERROR:
                    return REQUEST_EVENT_CMD_ERROR;
                    
                case REQUEST_EVENT_RSV_OK:
                    client->parsing_state.request.rsv = c;
                    break;
                    
                case REQUEST_EVENT_ATYP_OK:
                    client->parsing_state.request.atyp = (socks5_atyp)c;
                    client->request_info.atyp = (socks5_atyp)c;
                    client->parsing_state.request.addr_bytes_read = 0;
                    
                    
                    if (c == ATYP_IPV4) {
                        client->parsing_state.request.addr_len = 4;
                    } else if (c == ATYP_IPV6) {
                        client->parsing_state.request.addr_len = 16;
                    }
                    else if (c == ATYP_DOMAINNAME) {
                        client->parsing_state.request.addr_len = 0; 
                    } else {
                        return REQUEST_EVENT_ATYP_ERROR; 
                    }
                    break;
                    
                case REQUEST_EVENT_ATYP_ERROR:
                    return REQUEST_EVENT_ATYP_ERROR;
                    break;
                case REQUEST_EVENT_ADDR_PORT_BYTE_OK:
                    if (client->parsing_state.request.atyp == ATYP_DOMAINNAME && client->parsing_state.request.addr_bytes_read == 0) {
                       
                        client->parsing_state.request.addr_len = c;
                        client->parsing_state.request.addr_bytes_read++;
                    } else {
                       
                        int expected_addr_bytes = client->parsing_state.request.addr_len;
                        if (client->parsing_state.request.atyp == ATYP_DOMAINNAME) {
                            expected_addr_bytes++; 
                        }
                        
                        if (client->parsing_state.request.addr_bytes_read < expected_addr_bytes) {
                         
                            if (client->parsing_state.request.atyp == ATYP_DOMAINNAME) {
                                client->parsing_state.request.temp_addr[client->parsing_state.request.addr_bytes_read - 1] = c;
                            } else {
                                client->parsing_state.request.temp_addr[client->parsing_state.request.addr_bytes_read] = c;
                            }
                            client->parsing_state.request.addr_bytes_read++;
                            
                            if (client->parsing_state.request.addr_bytes_read == expected_addr_bytes) {
                                if (client->parsing_state.request.atyp == ATYP_DOMAINNAME) {
                                    client->parsing_state.request.temp_addr[client->parsing_state.request.addr_len] = '\0';
                                    strcpy(client->request_info.dest_addr, client->parsing_state.request.temp_addr);
                                } else {
                                    if (client->parsing_state.request.atyp == ATYP_IPV4) {
                                        inet_ntop(AF_INET, client->parsing_state.request.temp_addr, 
                                                client->request_info.dest_addr, sizeof(client->request_info.dest_addr));
                                    } else if (client->parsing_state.request.atyp == ATYP_IPV6) {
                                        inet_ntop(AF_INET6, client->parsing_state.request.temp_addr, 
                                                client->request_info.dest_addr, sizeof(client->request_info.dest_addr));
                                    }
                                }
                                client->parsing_state.request.port_bytes_read = 0;
                            }
                        } else {
                            if (client->parsing_state.request.port_bytes_read < 2) {
                                client->parsing_state.request.temp_port[client->parsing_state.request.port_bytes_read] = c;
                                client->parsing_state.request.port_bytes_read++;
                                
                                if (client->parsing_state.request.port_bytes_read == 2) {
                                    client->request_info.dest_port = ntohs(*(uint16_t*)client->parsing_state.request.temp_port);
                                
                                    memset(&client->parsing_state.request, 0, sizeof(client->parsing_state.request));
                                    return REQUEST_EVENT_DONE;
                                }
                            }
                        }
                    }
                    break;
                    
                case REQUEST_EVENT_ERROR:
                default:
                    return REQUEST_EVENT_ERROR;
            }
        }
    }

    return last_event;
}

int generate_request_response(struct buffer *write_buffer, socks5_reply reply, 
                             socks5_atyp atyp, const char *bind_addr, uint16_t bind_port) {
    size_t write_space;
    uint8_t *write_ptr = buffer_write_ptr(write_buffer, &write_space);
    
    size_t response_size = 6; 
    if (atyp == ATYP_IPV4) {
        response_size += 4;
    } else if (atyp == ATYP_IPV6) {
        response_size += 16;
    } else if (atyp == ATYP_DOMAINNAME) {
        response_size += 1 + strlen(bind_addr); 
    }
    
    if (write_space < response_size) {
        return -1; 
    }
    
    // Build response
    write_ptr[0] = SOCKS_VERSION; // VER
    write_ptr[1] = reply; // REP
    write_ptr[2] = 0x00; // RSV
    write_ptr[3] = atyp; // ATYP
    
    size_t offset = 4;
    
  
    if (atyp == ATYP_IPV4) {
        struct in_addr addr;
        inet_pton(AF_INET, bind_addr, &addr);
        memcpy(write_ptr + offset, &addr, 4);
        offset += 4;
    } else if (atyp == ATYP_IPV6) {
        struct in6_addr addr;
        inet_pton(AF_INET6, bind_addr, &addr);
        memcpy(write_ptr + offset, &addr, 16);
        offset += 16;
    } else if (atyp == ATYP_DOMAINNAME) {
        uint8_t len = strlen(bind_addr);
        write_ptr[offset++] = len;
        memcpy(write_ptr + offset, bind_addr, len);
        offset += len;
    }

    uint16_t net_port = htons(bind_port);
    memcpy(write_ptr + offset, &net_port, 2);
    
    buffer_write_adv(write_buffer, response_size);
    
    return 0; 
}
