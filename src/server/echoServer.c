#include <stdio.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "../shared/selector.h"
#include "selectorHandle.h"

#define ERROR_CODE 1 // @TODO Handle different error codes

#define MAX_CONNECTIONS 512

#define PORT 1080 // @TODO Remove


/**
 * 1. Set up socket for socks5 protocol and listen for incoming connections
 * 2. @TODO set up socket for protocol of our own and listen for incoming connections
 * 3. Set up selector 
 * 
 * @TODO Better handle for resource cleanup
 * 
 */
int main(){
    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;
    int socks5socket = socket(AF_INET6, SOCK_STREAM, 0);
    if(socks5socket < 0){
        perror("Error opening socket\n");
        return ERROR_CODE;
    }

    // ** Disable IPv6 Only Config
    if(setsockopt(socks5socket, IPPROTO_IPV6, IPV6_V6ONLY, &(int) { 0 }, sizeof(int)) < 0){
        perror("Error setting disabling IPv6 Only Configuration\n");
        close(socks5socket);
        return ERROR_CODE;
    }

    // ** Enable address reuse
    if(setsockopt(socks5socket, SOL_SOCKET, SO_REUSEADDR, &(int) { 1 }, sizeof(int)) < 0){
        perror("Error setting enabling Reuse Address Configuration\n");
        close(socks5socket);
        return ERROR_CODE;
    }

    struct sockaddr_in6 sockaddr = {0};
    sockaddr.sin6_family = AF_INET6;
    sockaddr.sin6_addr = in6addr_any;
    sockaddr.sin6_port = htons(PORT);

    if(bind(socks5socket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0){
        perror("Error binding socket\n");
        close(socks5socket);
        return ERROR_CODE;
    }

    if(listen(socks5socket, MAX_CONNECTIONS) < 0){
        perror("Error listening\n");
        close(socks5socket);
        return ERROR_CODE;
    }

    printf("Socket listening on TCP port %d\n", PORT);

    /**
     * @TODO:
     * Setup socket for our own protocol
     */

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0,
        },
    };

    if((ss = selector_init(&conf)) != SELECTOR_SUCCESS){
        perror(selector_error(ss));
        close(socks5socket);
        return ERROR_CODE;
    }

    selector = selector_new(1024);
    if(selector == NULL){
        perror("Unable to create selector\n");
        selector_close();
        close(socks5socket);
        return ERROR_CODE;
    }

    fd_handler handle_passive_socket = {
        .handle_read = handle_read,
        .handle_write = NULL,
        .handle_close = NULL,
        .handle_block = NULL
    };

    ss = selector_register(selector, socks5socket, &handle_passive_socket, OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS){
        printf("Error selecting: %s\n", selector_error(ss));
        close(socks5socket);
        selector_destroy(selector);
        selector_close();
        return ERROR_CODE;
    }

    while(1){
        ss = selector_select(selector);

        if(ss != SELECTOR_SUCCESS){
            printf("Error selecting: %s\n", selector_error(ss));
            close(socks5socket);
            selector_destroy(selector);
            selector_close();
            return ERROR_CODE;
        }
    }
    /**
     *  @TODO
     *  Handle server behaviour
     */

     
    // Cleaning resources...
    selector_destroy(selector);
    selector_close();
    close(socks5socket);
}