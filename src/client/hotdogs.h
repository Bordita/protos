#ifndef __hotdogs_h_
#define __hotdogs_h_

#include "../shared/includes/HotDogsProtocolTypes.h"

#define SUCCESS_CONNECTING 0
#define UNSUCCESSFUL_CONNECTION 1

typedef enum {
    ACTION_NONE,
    ACTION_GET_METRICS,
    ACTION_GET_USERS,
    ACTION_GET_LOGS,
    ACTION_PUT_BUFFER,
    ACTION_ADD_USER,
    ACTION_REMOVE_USER
} ActionType;

typedef struct Action{
    ActionType type;
    union {
        struct { int value; } timeout;
        struct { int value; } buffer;
        struct { char *user; char *pass; } add_user;
        struct { char *user; } remove_user;
    } data;
    response_status (*execute)(struct Action * action);
} Action;

void print_error_msg(response_status status);

int authenticate(char * uname, char * pass, char * addr, int port);

response_status recv_mod_res(mod_option optn);
response_status execute_get_request(ReqMethod req, retr_option opt);
response_status recv_and_print_data(retr_option optn, uint16_t len);

response_status execute_get_metrics(Action * action);
response_status execute_get_users(Action * action);
response_status execute_get_logs(Action * action);
response_status execute_put_buffer(Action * action);
response_status execute_add_user(Action * action);
response_status execute_remove_user(Action * action);

#endif
