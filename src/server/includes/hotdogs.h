#ifndef __HOTDOGS_SERVER_H__
#define __HOTDOGS_SERVER_H__

#define MAX_HOTDOGS_BUFFER_SIZE 1024
#define BUFFER_SIZE_BYTES_SOCKS5 2

#define SEPARATOR "\r"
#define SEPARATOR_SIZE 1

#define MAX_DATA_SIZE 65535


#include <netdb.h>
#include <stdint.h>
#include <sys/socket.h>
#include "../../shared/buffer.h"
#include "../../shared/stm.h"
#include "../../shared/selector.h"
#include "../../shared/HotDogsProtocolTypes.h"


typedef enum {
    HOTDOGS_AUTH = 0,
    HOTDOGS_AUTH_RESPONSE,
    HOTDOGS_REQUEST,
    HOTDOGS_RESPONSE,
    HOTDOGS_DONE,
    HOTDOGS_ERROR
} hotdogs_states;

typedef enum {
    HOTDOGS_PARSE_VERSION,
    HOTDOGS_PARSE_ULEN,
    HOTDOGS_PARSE_USERNAME,
    HOTDOGS_PARSE_PLEN,
    HOTDOGS_PARSE_PASSWORD,
    HOTDOGS_PARSE_METHOD,
    HOTDOGS_PARSE_OPTIONS,
    HOTDOGS_PARSE_NEWBUFFSIZE,
    HOTDOGS_PARSE_DONE,
    HOTDOGS_PARSE_ERROR
} hotdogs_parse_event;

typedef struct {
    int client_socket;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    
    // Buffers
    buffer read_buffer;
    buffer write_buffer;
    uint8_t *raw_buffer_a;
    uint8_t *raw_buffer_b;
    
    // State machine
    struct state_machine stm;
    
    // Auth info
    AuthenticationStatus authenticated;
    char username[MAX_UNAME_LEN + 1];
    
    // Actual request method
    ReqMethod current_method;
    uint8_t current_option;
    response_status current_response_status;
    

    /** Parsers */
    // Parser for the authentication
    struct auth_parser {
        hotdogs_parse_event current_parse_state;
        uint8_t username_len;
        uint8_t username_remaining;
        uint8_t password_len;
        uint8_t password_remaining;
        char username[MAX_UNAME_LEN + 1];
        char password[MAX_PASS_LEN + 1];
    }auth_parser;

    // Parser for the requests
    struct request_parser {
        ReqMethod current_method;
        uint8_t current_option;

        hotdogs_parse_event current_parse_state;
        
        uint8_t username_len;
        uint8_t username_remaining;
        uint8_t password_len;
        uint8_t password_remaining;
        char username[MAX_UNAME_LEN + 1];
        char password[MAX_PASS_LEN + 1];

        uint16_t new_buffer_size;
        uint8_t buffer_size_bytes_remaining;
    }request_parser;


    // Para evitar cierre múltiple
    bool dont_close;
} client_hotdogs;

const struct state_definition * get_hotdogs_states(void);
void close_hotdogs_connection(struct selector_key *key);
void init_hotdogs_client(client_hotdogs *client, int client_socket);

#endif
