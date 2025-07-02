#ifndef __hot_dogs_protocol_types_h_
#define __hot_dogs_protocol_types_h_

typedef enum AuthenticationStatus{
    AUTH_SUCCESS = 0,
    UNDERCOOKED,
    BURNT,
    WHO_LET_BRO_COOK
} AuthenticationStatus;

typedef enum ReqMethod{
    GET = 0,
    PUT
} ReqMethod;

typedef enum GetOptions{
    METRICS = 0,
    LIST_USERS,
    LIST_LOGS
} GetOptions;

typedef enum PutOptions{
    BUF_SIZE,
    TIMEOUT,
    ADD_USER,
    REMOVE_USER
} PutOptions;

typedef enum ResponseStatus{
    SUCCESS_RESPONSE = 0,
    NO_BUN_FOUND,
    BAD_TOPPING,
    NO_SUCH_BUN,
    WHO_LET_BRO_COOK_RESPONSE
} ResponseStatus;

#endif