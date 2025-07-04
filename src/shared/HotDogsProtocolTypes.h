#ifndef __hot_dogs_protocol_types_h_
#define __hot_dogs_protocol_types_h_

#define MAX_UNAME_LEN 255
#define MAX_PASS_LEN 255

#define METRICS_RESPONSE_LEN 16
#define DATA_LEN 2

#define BASE_RESPONSE_LEN 3
#define BASE_REQUEST_LEN 2

#define AUTH_RESPONSE_LEN 2
#define VERSION 1

typedef enum AuthenticationStatus{
    AUTH_SUCCESS = 0,
    UNDERCOOKED,
    BURNT,
    WHO_LET_BRO_COOK
} AuthenticationStatus;

typedef enum ReqMethod{
    RETR = 0,
    MOD
} ReqMethod;

typedef enum retr_option{
    METRICS = 0,
    LIST_USERS,
    LIST_LOGS
} retr_option;

typedef enum mod_option{
    BUF_SIZE,
    TIMEOUT,
    ADD_USER,
    REMOVE_USER
} mod_option;

typedef enum response_status{
    SUCCESS_RESPONSE = 0,
    NO_BUN_FOUND,
    BAD_TOPPING,
    NO_SUCH_BUN,
    WHO_LET_BRO_COOK_RESPONSE
} response_status;

#endif