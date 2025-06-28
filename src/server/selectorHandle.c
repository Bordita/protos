#include "selectorHandle.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define BUFLIMIT 256

void handle_client_read(struct selector_key * key);
void handle_client_write(struct selector_key * key);
void handle_client_close(struct selector_key * key);

static const fd_handler client_struct_handler = {
    .handle_read = handle_client_read,
    .handle_write = handle_client_write,
    .handle_close = handle_client_close,
    .handle_block = NULL
};

void handle_client_read(struct selector_key * key){
    Client *client = (Client *)key->data;
    if (client == NULL) return;

    size_t nbytes;
    uint8_t *write_ptr = buffer_write_ptr(&client->input, &nbytes);
    if (nbytes == 0) {
        buffer_compact(&client->input);
        write_ptr = buffer_write_ptr(&client->input, &nbytes);
        if (nbytes == 0) return;
    }

    ssize_t r = read(client->fd, write_ptr, nbytes);
    if (r > 0) {
        buffer_write_adv(&client->input, r);

        // @TODO Remove this, this is only because this is an echo TCP Server
        size_t to_copy = r;
        size_t out_nbytes;
        uint8_t *out_ptr = buffer_write_ptr(&client->output, &out_nbytes);
        if (out_nbytes < to_copy) to_copy = out_nbytes;
        memcpy(out_ptr, write_ptr, to_copy);
        buffer_write_adv(&client->output, to_copy);

        if (buffer_can_read(&client->output)) {
            selector_set_interest_key(key, OP_READ | OP_WRITE);
        }
    } else if (r == 0) {
        selector_unregister_fd(key->s, client->fd);
    } else {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("read");
            selector_unregister_fd(key->s, client->fd);
        }
    }
}

void handle_client_write(struct selector_key * key){
    Client *client = (Client *)key->data;
    if (client == NULL) return;

    size_t nbytes;
    uint8_t *read_ptr = buffer_read_ptr(&client->output, &nbytes);
    if (nbytes == 0) {
        selector_set_interest_key(key, OP_READ);
        return;
    }

    ssize_t w = write(client->fd, read_ptr, nbytes);
    if (w > 0) {
        buffer_read_adv(&client->output, w);
        if (!buffer_can_read(&client->output)) {
            selector_set_interest_key(key, OP_READ);
        }
    } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        perror("write");
        selector_unregister_fd(key->s, client->fd);
    }
}

void handle_client_close(struct selector_key * key){
    Client * current = (Client*)key->data;
    free(current->input.data);
    free(current->output.data);
    int fd = current->fd;
    free(current);
    close(fd);
}

Client * create_client(int fd, struct sockaddr_in6 * addr, int addr_len){
    Client * new = calloc(sizeof(Client), 1);
    if(new == NULL){
        return NULL;
    }
    new->addrlen = addr_len;
    new->fd = fd;
    memcpy(&(new->addr), addr, sizeof(new->addr));
    
    buffer_init(&new->input, BUFLIMIT, malloc(BUFLIMIT));
    buffer_init(&new->output, BUFLIMIT, malloc(BUFLIMIT));

    return new;
}

void accept_pasive_socket(struct selector_key * key){
    struct sockaddr_in6 client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if(client_fd == -1){
        perror("Error accepting socket\n");
        return; // ERROR
    }

    if(selector_fd_set_nio(client_fd) == -1){
        perror("Error setting selector nio\n");
        close(client_fd);
        return;
    }

    Client * newClient = create_client(client_fd, &client_addr, client_addr_len);
    if(newClient == NULL){
        perror("Error creating client\n");
        close(client_fd);
        return;
    }

    if(selector_register(key->s, client_fd, &client_struct_handler, OP_READ, newClient) != SELECTOR_SUCCESS) {
        perror("Error registering selector\n");
        // @TODO FREE RESOURCES
        return;
    } 
}

void handle_read(struct selector_key * key){
    accept_pasive_socket(key);
}

void handle_write(struct selector_key * key){

}