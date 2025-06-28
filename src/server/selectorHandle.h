#ifndef __selector_handle_h
#define __selector_handle_h

#include "../shared/selector.h"
#include "../shared/buffer.h"
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct client {
    int fd;
    socklen_t addrlen;
    struct sockaddr_in6 addr;

    buffer input;
    buffer output;
} Client;

void handle_read(struct selector_key * key);

#endif