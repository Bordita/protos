#ifndef __server_handler_h
#define __server_handler_h

#define SELECTOR_TIMEOUT 100
#define INITIAL_SELECTOR_ITEMS 20
#define LISTEN_MAX_QUEUE 50
#define MAX_FDS 1023
#define SERVER_LISTEN_SOCKET_COUNT 4
#define FDS_PER_SOCKS_CONNECTION 2
#define FDS_RESERVED_BY_OS 2
#define LOCALHOST_ADDR_IPV4 "127.0.0.1"
#define LOCALHOST_ADDR_IPV6 "::1"


int server_handler(char * socks_addr, char * socks_port, char * mng_addr,char * mng_port);

const fd_handler * get_connection_fd_handler(void);
void server_handler_free(void);
#endif


