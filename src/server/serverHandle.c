#include <netdb.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <string.h>   
#include <signal.h>  
#include "../shared/includes/stm.h"
#include "../shared/includes/buffer.h"
#include "../shared/includes/parser.h"
#include "../shared/includes/selector.h"
#include "serverHandle.h"
#include "../shared/includes/metrics.h"
#include "greeting.h"
#include "socks5.h"
#include "./includes/hotdogs.h"

typedef enum {
    SOCKET_TYPE_SOCKS5,
    SOCKET_TYPE_HOTDOGS,
    SOCKET_TYPE_UNKNOWN
} socket_type;

static char * error_msg;
static fd_selector selector;

// Passive sockets file descriptors
static int fd_socks = -1;
static int fd_hot_dogs = -1;


// Socks5 handlers
void close_connection(client_socks5 * client) {
    if (client->dont_close)
        return;
    client->dont_close = true;

    int client_socket = client->client_socket;
    int server_socket = client->destination_socket;

 
    if (server_socket != -1) {
        selector_unregister_fd(selector, server_socket);
        close(server_socket);
    }
    if (client_socket != -1) {
        selector_unregister_fd(selector, client_socket);
        close(client_socket);
    }

    if (client->resolved_addr != NULL) {
        freeaddrinfo(client->resolved_addr);
    }

    buffer_reset(&client->read_buffer);
    buffer_reset(&client->write_buffer);
    
    free(client->client_to_dest_buffer.data);
    free(client->dest_to_client_buffer.data);
    
    free(client->raw_buffer_a);
    free(client->raw_buffer_b);
    free(client);
    remove_socks5_current_connection();
}

static void connection_read(struct selector_key *key) {
    client_socks5 * client = (client_socks5 *)key->data;
    socks5_states state = stm_handler_read(&client->stm, key);

    if (state == ERROR || state == DONE || state == BAD_CREDENTIALS) {
        close_connection(client);
    }
    if(state == ERROR) {
        add_failed_connection();
    }
}

static void connection_write(struct selector_key *key) {
    client_socks5 * client = (client_socks5 *)key->data;
    socks5_states state = stm_handler_write(&client->stm, key);

    if (state == ERROR || state == DONE || state == BAD_CREDENTIALS) {
        close_connection(client);
    }
    if(state == ERROR) {
        add_failed_connection();
    }
}

static void connection_block(struct selector_key *key) {
    client_socks5 * client = (client_socks5 *)key->data;
    socks5_states state = stm_handler_block(&client->stm, key);

    if (state == ERROR || state == DONE || state == BAD_CREDENTIALS) {
        close_connection(client);
    }
    if(state == ERROR) {
        add_failed_connection();
    }
}

static void connection_close(struct selector_key *key) {
    client_socks5 * client = (client_socks5 *)key->data;
    close_connection(client);
}

static const fd_handler socks_connection_fd_handler = {
    .handle_read = connection_read,
    .handle_write = connection_write,
    .handle_block = connection_block,
    .handle_close = connection_close
};

// Hotdogs handlers

static void hotdogs_connection_read(struct selector_key *key) {
    client_hotdogs * client = (client_hotdogs *)key->data;
    stm_handler_read(&client->stm, key);
}

static void hotdogs_connection_write(struct selector_key *key) {
    client_hotdogs * client = (client_hotdogs *)key->data;
    stm_handler_write(&client->stm, key);
}

static void hotdogs_connection_close(struct selector_key *key) {
    close_hotdogs_connection(key);
    remove_hdp_current_connection();
}

static const fd_handler hotdogs_connection_fd_handler = {
    .handle_read = hotdogs_connection_read,
    .handle_write = hotdogs_connection_write,
    .handle_block = NULL,
    .handle_close = hotdogs_connection_close
};


//server
static void passive_socket_handler(struct selector_key *key) {
    int fd = key->fd;
    socket_type type = SOCKET_TYPE_UNKNOWN;

    if (fd == fd_socks) {
        type = SOCKET_TYPE_SOCKS5;
    } else if (fd == fd_hot_dogs) {
        type = SOCKET_TYPE_HOTDOGS;
    }

    int fds_in_use = get_socks5_current_connections() * FDS_PER_SOCKS_CONNECTION + get_hdp_current_connections() + SERVER_LISTEN_SOCKET_COUNT;
    
    switch (type){
        case SOCKET_TYPE_SOCKS5:
            if ((MAX_FDS - fds_in_use) < FDS_PER_SOCKS_CONNECTION) {
                int new_fd;
                if ((new_fd = accept(fd, NULL, NULL)) != -1) {
                    close(new_fd);
                }
                return;
            }
            
            client_socks5 * client = malloc(sizeof(client_socks5));
            if (client == NULL) {
                perror("malloc error");
                return;
            }

            uint32_t buffer_size = socks_get_buffer_size();

            // Struct initialization
            memset(client, 0x00, sizeof(*client));
            client->raw_buffer_a = malloc(buffer_size);
            client->raw_buffer_b = malloc(buffer_size);
            buffer_init(&client->read_buffer, buffer_size, client->raw_buffer_a);
            buffer_init(&client->write_buffer, buffer_size, client->raw_buffer_b);

            // Inicializar campos para conexiones robustas
            client->connection_attempts = 0;
            client->resolved_addr = NULL;
            client->resolved_addr_current = NULL;
            client->destination_socket = -1;
            client->stm.initial = GREETING_READ;
            client->stm.max_state = DONE;
            client->stm.states = get_socks5_states();

            stm_init(&client->stm);

            client->client_addr_len = sizeof(client->client_addr);
            client->client_socket = accept(fd, (struct sockaddr *)&client->client_addr,&client->client_addr_len);
            add_socks5_current_connection();

            if (client->client_socket == -1) {
                perror("Couldn't connect to client");
                close_connection(client);
                return;
            }
            selector_fd_set_nio(client->client_socket);

            if (selector_register(selector, client->client_socket, &socks_connection_fd_handler,OP_READ, client)) {
                perror("selector_register error");
                close_connection(client);
                return;
            }
            break;
        case SOCKET_TYPE_HOTDOGS:
            if ((MAX_FDS - fds_in_use) < 1) {
                int new_fd;
                if ((new_fd = accept(fd, NULL, NULL)) != -1) {
                    close(new_fd);
                }
                return;
            }
            
            client_hotdogs * hotdogs_client = malloc(sizeof(client_hotdogs));
            if (hotdogs_client == NULL) {
                perror("malloc error");
                return;
            }

            init_hotdogs_client(hotdogs_client, -1);

            // Accept hdp connection
            hotdogs_client->client_addr_len = sizeof(hotdogs_client->client_addr);
            hotdogs_client->client_socket = accept(fd, (struct sockaddr *)&hotdogs_client->client_addr, &hotdogs_client->client_addr_len);
            if (hotdogs_client->client_socket == -1) {
                perror("Couldn't connect to HotDogs client");
                clear_hotdogs_client(hotdogs_client);
                return;
            }
            
            selector_fd_set_nio(hotdogs_client->client_socket);

            if (selector_register(selector, hotdogs_client->client_socket, &hotdogs_connection_fd_handler, OP_READ, hotdogs_client)) {
                perror("selector_register error");
                close(hotdogs_client->client_socket);
                clear_hotdogs_client(hotdogs_client);
                return;
            }
            
            add_hdp_current_connection();
            break;
        case SOCKET_TYPE_UNKNOWN:
            fprintf(stderr, "Unknown socket type for fd %d\n", fd);
            close(fd);
            break;
    }
}

const struct fd_handler passive_socket_fd_handler = {passive_socket_handler,0,0,0};

static int create_socket(char * addr, char * port,const struct fd_handler * selector_handler,int family){
    struct addrinfo hint, *res = NULL;
    int ret, fd;
    bool error = false;
    int ipv6_only = 1, reuse_addr = 1;

    memset(&hint, 0, sizeof(hint));

    hint.ai_family = family;
    hint.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

    ret = getaddrinfo(addr, port, &hint, &res);
    if (ret) {
        fprintf(stderr, "unable to get address info: %s", gai_strerror(ret));
        error = true;
        goto finally;
    }

    fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
        error_msg = "unable to create socket";
        error = true;
        goto finally;
    }

    ret = selector_fd_set_nio(fd);
    if (ret == -1) {
        error_msg = "unable to set socket to non-blocking";
        error = true;
        goto finally;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(int)) == -1) {
        error_msg = "unable to set socket to reuse address";
        error = true;
        goto finally;
    }

    if (family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,&ipv6_only, sizeof(int)) == -1) {
        error_msg = "unable to set socket to ipv6_only";
        error = true;
        goto finally;
    }

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        error_msg = "bind passive socket error";
        error = true;
        goto finally;
    }

    if (listen(fd, LISTEN_MAX_QUEUE) < 0) {
        error_msg = "listen passive socket error";
        error = true;
        goto finally;
    }

    int register_ret;
    if ((register_ret = selector_register(selector, fd, selector_handler,OP_READ, NULL)) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Passive socket register error: %s",selector_error(register_ret));
        error = true;
        goto finally;
    }

finally:
    if (error && fd != -1) {
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    return fd;
}



//selector
int server_handler(char * socks_addr, char * socks_port, char * hot_dogs_addr,char * hot_dogs_port){

    error_msg = NULL;
    int ret_code = 0;
    int selector_init_ret;

    struct timespec selector_timeout = {0};
    selector_timeout.tv_sec = SELECTOR_TIMEOUT;
    struct selector_init selector_init_struct = {SIGALRM, selector_timeout};
    
     if ((selector_init_ret = selector_init(&selector_init_struct)) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Selector init error: %s",selector_error(selector_init_ret));
        goto finally;
    }
    selector = selector_new(INITIAL_SELECTOR_ITEMS);
    if (selector == NULL) {
        error_msg = "Error creating the selector";
        goto finally;
    }

    if ((fd_socks = create_socket(socks_addr,socks_port,&passive_socket_fd_handler,AF_UNSPEC)) == -1){   
        goto finally;
    }

    if ((fd_hot_dogs = create_socket(hot_dogs_addr,hot_dogs_port,&passive_socket_fd_handler,AF_UNSPEC)) == -1){   
        goto finally;
    }

    while (1) {
        int selector_status = selector_select(selector);
        if (selector_status != SELECTOR_SUCCESS){
            fprintf(stderr, "Selector Select Error: %s",selector_error(selector_status));
            goto finally;
        }
    }

finally:
    if (error_msg) {
        perror(error_msg);
        ret_code = -1;
    }

    if (fd_socks != -1)
        close(fd_socks);
    if (fd_hot_dogs != -1)
        close(fd_hot_dogs);
    return ret_code;
}

const fd_handler * get_connection_fd_handler(void) {
    return &socks_connection_fd_handler;
}

void server_handler_free(void) {
     selector_destroy(selector);
     selector_close();
}
