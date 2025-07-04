#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include "./hotdogs.h"

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
        fprintf(stderr, "[Error] Either username, password or server address for authenticating are not valid\n");
        return UNSUCCESSFUL_CONNECTION;
    }
    int uname_len = strlen(uname);
    int pass_len = strlen(pass);
    if(uname_len > MAX_UNAME_LEN || pass_len > MAX_PASS_LEN){
        fprintf(stderr, "[Error] Username or password are longer than 255 characters\n");
        return UNSUCCESSFUL_CONNECTION;
    }
    
    if(connect_socket(addr, port) != SUCCESS_CONNECTING){
        fprintf(stderr, "[Error] Error connecting %s:%d\n", addr, port);
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
        fprintf(stderr, "[Error] Authentication: Unable to send credentials\n");
        return UNSUCCESSFUL_CONNECTION;
    }

    uint8_t ans[AUTH_RESPONSE_LEN] = {0};
    if(recv(fd, ans, AUTH_RESPONSE_LEN, MSG_WAITALL) < 0){
        fprintf(stderr, "[Error] Authentication: Unable to receive authentication confirmation\n");
        return UNSUCCESSFUL_CONNECTION;
    }

    if(ans[0] != VERSION){
        fprintf(stderr, "[Error] Authentication: Version not accepted\n");
        return UNSUCCESSFUL_CONNECTION;
    }

    if(ans[1] != AUTH_SUCCESS){
        fprintf(stderr, "[Error] Authentication: Invalid credentials. Code %d\n", ans[1]);
        return UNSUCCESSFUL_CONNECTION;
    }

    return SUCCESS_CONNECTING;
}

ResponseStatus execute_get(ReqMethod req, GetOptions opt){
    uint8_t request[2] = {0};
    request[0] = (uint8_t)req;
    request[1] = (uint8_t)opt;
    if(send(fd, &request, 2, 0) < 0){
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    uint8_t first_response[5] = {0};
    if(recv(fd, &first_response, 5, MSG_WAITALL) < 5){
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    if((uint8_t)first_response[2] != SUCCESS_RESPONSE) {
       return (uint8_t)first_response[2];
    }

    uint16_t data_len = *(uint16_t *)&first_response[3];
    uint8_t * data = malloc(data_len);
    if(data == NULL){
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    if(recv(fd, data, data_len, MSG_WAITALL) < data_len){
        free(data);
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    // Do something with the data, maybe print it idk, should rethink it.
    fwrite(data, 1, data_len, stdout);
    printf("\n");

    free(data);
    return SUCCESS_RESPONSE;
}

ResponseStatus execute_get_metrics(Action * action){
    action->type = action->type;

    return execute_get(RETR, METRICS);
}

ResponseStatus execute_get_users(Action * action){
    action->type = action->type;

    return execute_get(RETR, LIST_USERS);
}

ResponseStatus execute_get_logs(Action * action){
    action->type = action->type;

    return execute_get(RETR, LIST_LOGS);
}

ResponseStatus execute_put_timeout(Action * action){
    action->type = action->type;
    printf("Executing put timeout\n");
    return 0;
}

ResponseStatus execute_put_buffer(Action * action){
    action->type = action->type;
    printf("Executing put buffer\n");
    return 0;
}

ResponseStatus execute_add_user(Action * action){
    action->type = action->type;
    printf("Executing add user\n");
    return 0;
}

ResponseStatus execute_remove_user(Action * action){
    action->type = action->type;
    printf("Executing remove user\n");
    return 0;
}

void print_error_msg(ResponseStatus status){
    if(status == SUCCESS_RESPONSE){
        return;
    }
    
    switch(status){
        case NO_BUN_FOUND: 
            fprintf(stderr, "[Error] Invalid Method\n");
            return;
        case BAD_TOPPING:
            fprintf(stderr, "[Error] Invalid Operation\n");
            return;
        case NO_SUCH_BUN:
            fprintf(stderr, "[Error] User not found\n");
            return;
        case WHO_LET_BRO_COOK_RESPONSE:
            fprintf(stderr, "[Error] Generic Server Error\n");
    }
}