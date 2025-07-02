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
    int (*execute)(struct Action * action);
} Action;

int authenticate(char * uname, char * pass, char * addr, int port);

int execute_get_metrics(Action * action);
int execute_get_users(Action * action);
int execute_get_logs(Action * action);
int execute_put_timeout(Action * action);
int execute_put_buffer(Action * action);
int execute_add_user(Action * action);
int execute_remove_user(Action * action);


#endif