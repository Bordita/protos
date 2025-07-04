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
    if(recv(fd, &ans, AUTH_RESPONSE_LEN, MSG_WAITALL) < 0){
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

response_status execute_get_metrics(Action * action){
    (void)action;
    response_status request_status = execute_get_request(RETR, METRICS);
    if(request_status != SUCCESS_RESPONSE){
        return request_status;
    }

    uint8_t res[BASE_RESPONSE_LEN + METRICS_RESPONSE_LEN];
    if(recv(fd, &res, BASE_RESPONSE_LEN + METRICS_RESPONSE_LEN, MSG_WAITALL) < (BASE_RESPONSE_LEN + METRICS_RESPONSE_LEN)){
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    if(res[0] != RETR || res[1] != METRICS){
        return WHO_LET_BRO_COOK_RESPONSE;
    } else if (res[2] != SUCCESS_RESPONSE){
        return res[2];
    }

    uint32_t historic_connections = *(uint32_t*)&res[BASE_RESPONSE_LEN];
    uint32_t current_connections = *(uint32_t*)&res[BASE_RESPONSE_LEN + 4];
    uint32_t failed_connections = *(uint32_t*)&res[BASE_RESPONSE_LEN + 4*2];
    uint32_t bytes_transfered = *(uint32_t*)&res[BASE_RESPONSE_LEN + 4*3];

    printf("Server metrics:\n");
    printf("  Historic connections: %u\n", historic_connections);
    printf("  Current connections: %u\n", current_connections);
    if (historic_connections > 0) {
        double fail_percentage = (double)failed_connections / historic_connections * 100.0;
        printf("  Fail percentage: %.2f%%\n", fail_percentage);
    } else {
        printf("  Fail percentage: N/A (no historic connections)\n");
    }
    printf("  Bytes transferred: %u\n", bytes_transfered);

    return SUCCESS_RESPONSE;
    
}

response_status execute_get_users(Action * action){
    (void)action;
    response_status request_status = execute_get_request(RETR, LIST_USERS);
    if(request_status != SUCCESS_RESPONSE){
        return request_status;
    }

    uint8_t first_res[BASE_RESPONSE_LEN + DATA_LEN];
    if(recv(fd, &first_res, BASE_RESPONSE_LEN + DATA_LEN, MSG_WAITALL) < (BASE_RESPONSE_LEN + DATA_LEN)){
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    if(first_res[0] != RETR || first_res[1] != METRICS){
        return WHO_LET_BRO_COOK_RESPONSE;
    } else if (first_res[2] != SUCCESS_RESPONSE){
        return first_res[2];
    }

    uint16_t data_len = *(uint16_t *)&first_res[BASE_RESPONSE_LEN];
    return recv_and_print_data(LIST_USERS, data_len);
}

response_status execute_get_logs(Action * action){
    (void)action;
    response_status request_status = execute_get_request(RETR, LIST_LOGS);
    if(request_status != SUCCESS_RESPONSE){
        return request_status;
    }
    
    uint8_t first_res[BASE_RESPONSE_LEN + DATA_LEN];
    if(recv(fd, &first_res, BASE_RESPONSE_LEN + DATA_LEN, MSG_WAITALL) < (BASE_RESPONSE_LEN + DATA_LEN)){
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    if(first_res[0] != RETR || first_res[1] != METRICS){
        return WHO_LET_BRO_COOK_RESPONSE;
    } else if (first_res[2] != SUCCESS_RESPONSE){
        return first_res[2];
    }

    uint16_t data_len = *(uint16_t *)&first_res[BASE_RESPONSE_LEN];
    return recv_and_print_data(LIST_LOGS, data_len);
}

response_status execute_put_buffer(Action * action){
    uint16_t new_size = (uint16_t)action->data.buffer.value;
    uint8_t req[BASE_REQUEST_LEN + 2] = {0};
    req[0] = MOD;
    req[1] = BUF_SIZE;
    req[2] = (new_size >> 8) & 0xFF;
    req[3] = new_size & 0xFF;

    if(send(fd, req, 4, 0) < 0){
        return WHO_LET_BRO_COOK_RESPONSE;
    }
    return recv_mod_res(BUF_SIZE);
}

response_status execute_add_user(Action * action){
    char *user = action->data.add_user.user;
    char *pass = action->data.add_user.pass;
    uint8_t uname_len = strlen(user);
    uint8_t pass_len = strlen(pass);
    uint8_t req[BASE_REQUEST_LEN + 2 + MAX_UNAME_LEN + MAX_PASS_LEN] = {0};
    size_t idx = 0;
    req[idx++] = MOD;
    req[idx++] = ADD_USER;
    req[idx++] = uname_len;
    memcpy(&req[idx], user, uname_len);
    idx += uname_len;
    req[idx++] = pass_len;
    memcpy(&req[idx], pass, pass_len);
    idx += pass_len;

    if(send(fd, req, idx, 0) < 0){
        return WHO_LET_BRO_COOK_RESPONSE;
    }
    return recv_mod_res(ADD_USER);
}

response_status execute_remove_user(Action * action){
    char *user = action->data.remove_user.user;
    uint8_t uname_len = strlen(user);
    uint8_t req[BASE_REQUEST_LEN + 1 + MAX_UNAME_LEN] = {0};
    size_t idx = 0;
    req[idx++] = MOD;
    req[idx++] = REMOVE_USER;
    req[idx++] = uname_len;
    memcpy(&req[idx], user, uname_len);
    idx += uname_len;

    if(send(fd, req, idx, 0) < 0){
        return WHO_LET_BRO_COOK_RESPONSE;
    }
    return recv_mod_res(REMOVE_USER);
}

void print_error_msg(response_status status){
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
        default:
            fprintf(stderr, "[Error] Generic Server Error\n");
    }
}

response_status recv_and_print_data(retr_option optn, uint16_t len){
    uint8_t * data = malloc(len);
    if(data == NULL){
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    if(recv(fd, data, len, MSG_WAITALL) < len){
        free(data);
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    switch(optn){
        case LIST_USERS:
            printf("Listing Server Users:\n");
            break;
        default:
            printf("Listing Server Logs:\n");
    }

    int entry = 1;
    char *token = strtok((char *)data, "\r");
    while(token != NULL) {
        printf("   [ %d ] %s\n", entry++, token);
        token = strtok(NULL, "\r");
    }

    free(data);
    return SUCCESS_RESPONSE;
}

response_status execute_get_request(ReqMethod req, retr_option opt){
    uint8_t request[2] = {0};
    request[0] = (uint8_t)req;
    request[1] = (uint8_t)opt;
    if(send(fd, &request, 2, 0) < 0){
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    return SUCCESS_RESPONSE;
}

response_status recv_mod_res(mod_option optn){
    uint8_t res[BASE_RESPONSE_LEN] = {0};

    if(recv(fd, &res, BASE_RESPONSE_LEN, MSG_WAITALL) < BASE_RESPONSE_LEN){
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    if(res[0] != MOD || res[1] != optn){
        return WHO_LET_BRO_COOK_RESPONSE;
    }

    return res[2];
}