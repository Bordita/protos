#ifndef __socks_h
#define __socks_h

#include <netdb.h>
#include <stdint.h>
#include <sys/socket.h>
#include "../shared/buffer.h"
#include "../shared/parser.h"
#include "../shared/stm.h"
#include "../shared/selector.h"

#define MAX_SOCKS5_BUFFER_SIZE 1024

static const uint8_t SOCKS_VERSION = 0x05;


// SOCKS5 Commands
typedef enum {
    CMD_CONNECT = 0x01,
    CMD_BIND = 0x02,           // Not supported
    CMD_UDP_ASSOCIATE = 0x03   // Not supported
} socks5_cmd;

// Address Types
typedef enum {
    ATYP_IPV4 = 0x01,
    ATYP_DOMAINNAME = 0x03,
    ATYP_IPV6 = 0x04
} socks5_atyp;

//Authentication Methods
typedef enum {
    METHOD_NO_AUTHENTICATION_REQUIRED = 0x00,
    METHOD_USERNAME_PASSWORD = 0x02,
    METHOD_NO_ACCEPTABLE_METHODS = 0xFF,
} authentication_method;


// State machine states for SOCKS5
typedef enum {
    GREETING_READ,         
    GREETING_WRITE,
    AUTHENTICATION_READ,
    AUTHENTICATION_WRITE,
    REQUEST_READ,
    REQUEST_RESOLV,
    REQUEST_CONNECT,
    REQUEST_WRITE,
    RELAY_DATA,
    ERROR,
    DONE,
    BAD_CREDENTIALS
} socks5_states;


typedef struct {
    char username[256];
    char password[256];
} credentials;


typedef struct {
    char dest_addr[256];  
    uint16_t dest_port;    
    socks5_cmd cmd;       
    socks5_atyp atyp;      
} request_data;


// Parser authentication state
typedef struct {
    uint8_t version;
    uint8_t username_len;
    uint8_t password_len;
    uint8_t username_bytes_read;
    uint8_t password_bytes_read;
    char temp_username[256];
    char temp_password[256];
} auth_parsing_state;


// Parser greeting state
typedef struct greeting_parsing_state{
    uint8_t expected_methods;
    uint8_t methods_read;
    uint8_t received_methods[256];
} greeting_parsing_state;

// Parser request state
typedef struct {
    uint8_t version;
    socks5_cmd cmd;
    uint8_t rsv;
    socks5_atyp atyp;
    uint8_t addr_len;        
    uint8_t addr_bytes_read;
    uint8_t port_bytes_read;
    char temp_addr[256];
    uint8_t temp_port[2];      
} request_parsing_state;

typedef struct client_socks5 {
    // Client address
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_socket;


    // Destination address
    struct sockaddr_storage destination_addr;
    socklen_t destination_addr_len;
    int destination_socket;
    int destination_domain;

    // name resolution
    struct addrinfo * resolved_addr;
    struct addrinfo * resolved_addr_current;
    int connection_attempts;      

    // Buffers
    uint8_t * raw_buffer_a;
    uint8_t * raw_buffer_b;
    buffer read_buffer;
    buffer write_buffer;

    struct state_machine stm;

    struct parser* parser;

    // TODO
    // Add structs for relay data

    credentials auth_info;
    request_data request_info;

    union {
        greeting_parsing_state greeting;
        auth_parsing_state authentication;
        request_parsing_state request;
    } parsing_state;
    
    bool dont_close;

    authentication_method selected_method;

} client_socks5;


uint32_t socks_get_buffer_size(void);
const struct state_definition * get_socks5_states(void);

#endif
