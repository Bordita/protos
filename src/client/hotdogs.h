#ifndef __hotdogs_h_
#define __hotdogs_h_

#include "../shared/HotDogsProtocolTypes.h"

#define SUCCESS_CONNECTING 0
#define UNSUCCESSFUL_CONNECTION 1
#define MAX_UNAME_LEN 255
#define MAX_PASS_LEN 255
#define AUTH_RESPONSE_LEN 2
#define VERSION 1

typedef enum {
    ACTION_NONE,
    ACTION_GET_METRICS,
    ACTION_GET_USERS,
    ACTION_GET_LOGS,
    ACTION_PUT_TIMEOUT,
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
    ResponseStatus (*execute)(struct Action * action);
} Action;

void print_error_msg(ResponseStatus status);

int authenticate(char * uname, char * pass, char * addr, int port);

ResponseStatus execute_get(ReqMethod req, GetOptions opt);

ResponseStatus execute_get_metrics(Action * action);
ResponseStatus execute_get_users(Action * action);
ResponseStatus execute_get_logs(Action * action);
ResponseStatus execute_put_timeout(Action * action);
ResponseStatus execute_put_buffer(Action * action);
ResponseStatus execute_add_user(Action * action);
ResponseStatus execute_remove_user(Action * action);


#endif