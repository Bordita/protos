#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "./hotdogs.h"

static int version;
ReqMethod reqType = -1;
AuthenticationStatus authStatus = -1;
int options;

int fd = -1;

static int connect_socket(char * addr, int port){
    struct addrinfo hints, *res, *rp;
    char port_str[6];

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM; 

    if (getaddrinfo(addr, port_str, &hints, &res) != 0) {
        fprintf(stderr, "Error getting address info\n");
        return UNSUCCESSFUL_CONNECTION;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            continue;

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;

        close(fd);
    }

    freeaddrinfo(res);

    if (rp == NULL) {
        perror("connect");
        return UNSUCCESSFUL_CONNECTION;
    }

    return SUCCESS_CONNECTING;
}

int authenticate(char * uname, char * pass, char * addr, int port){
    if(uname == NULL || pass == NULL || addr == NULL){
        fprintf(stderr, "Error during authentication\n");
        return UNSUCCESSFUL_CONNECTION;
    }
    int uname_len = strlen(uname);
    int pass_len = strlen(pass);
    if(uname_len > MAX_UNAME_LEN || pass_len > MAX_PASS_LEN){
        fprintf(stderr, "Error, username or password are longer than 255 characters\n");
        return UNSUCCESSFUL_CONNECTION;
    }
    
    if(connect_socket(addr, port) != SUCCESS_CONNECTING){
        fprintf(stderr, "Error connecting %s:%d\n", addr, port);
        return UNSUCCESSFUL_CONNECTION;
    }

    // + 3: 1 for version, 1 for uname_len, 1 for pass_len
    uint8_t buffer[MAX_PASS_LEN + MAX_UNAME_LEN + 3] = {0};
    size_t buflen = 0;

    buffer[buflen++] = VERSION;

    buffer[buflen++] = uname_len;

    strncpy((char*)&buffer[buflen], uname, uname_len);
    buflen += uname_len;

    buffer[buflen++] = pass_len;

    strncpy((char*)&buffer[buflen], pass, pass_len);
    buflen += pass_len;

    if(send(fd, buffer, buflen, 0) < 0){
        fprintf(stderr, "Authentication error: Unable to send credentials\n");
        return UNSUCCESSFUL_CONNECTION;
    }

    uint8_t ans[AUTH_RESPONSE_LEN] = {0};
    if(recv(fd, ans, AUTH_RESPONSE_LEN, MSG_WAITALL) < 0){
        fprintf(stderr, "Authentication error: Unable to receive authentication confirmation\n");
        return UNSUCCESSFUL_CONNECTION;
    }

    if(ans[0] != VERSION){
        fprintf(stderr, "Authentication error: Version not accepted\n");
        return UNSUCCESSFUL_CONNECTION;
    }

    if(ans[1] != AUTH_SUCCESS){
        fprintf(stderr, "Authentication error: Invalid credentials. Code %d\n", ans[1]);
        return UNSUCCESSFUL_CONNECTION;
    }

    return SUCCESS_CONNECTING;
}

int execute_get_metrics(Action * action){
    printf("Executing get metrics\n");
    return 0;
}

int execute_get_users(Action * action){
    printf("Executing get users\n");
    return 0;
}

int execute_get_logs(Action * action){
    printf("Executing get logs\n");
    return 0;
}

int execute_put_timeout(Action * action){
    printf("Executing put timeout\n");
    return 0;
}

int execute_put_buffer(Action * action){
    printf("Executing put buffer\n");
    return 0;
}

int execute_add_user(Action * action){
    printf("Executing add user\n");
    return 0;
}

int execute_remove_user(Action * action){
    printf("Executing remove user\n");
    return 0;
}
