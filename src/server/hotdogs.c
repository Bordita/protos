#include "./includes/hotdogs.h"

#include "../shared/includes/metrics.h"
#include "../shared/includes/auth.h"
#include "../shared/includes/logger.h"
#include "../shared/includes/parser.h"
#include "./socks5.h"

#include <stdlib.h>
#include <string.h>

// Functions for each state
static unsigned hotdogs_auth_read(struct selector_key *key);
static unsigned hotdogs_auth_response(struct selector_key *key);
static unsigned hotdogs_request_read(struct selector_key *key);
static unsigned hotdogs_response_write(struct selector_key *key);
static unsigned hotdogs_done_handler(struct selector_key *key);
static unsigned hotdogs_error_handler(struct selector_key *key);

// Parser functions to requests read
static bool parse_request_method(client_hotdogs *client, uint8_t c);
static bool parse_request_options(client_hotdogs *client, uint8_t c);
static bool parse_request_retr_options(client_hotdogs *client, uint8_t c);
static bool parse_request_mod_options(client_hotdogs *client, uint8_t c);
static bool parse_request_bufsize(client_hotdogs *client, uint8_t c);
static bool parse_request_ulen(client_hotdogs *client, uint8_t c);
static bool parse_request_username(client_hotdogs *client, uint8_t c);
static bool parse_request_plen(client_hotdogs *client, uint8_t c);
static bool parse_request_password(client_hotdogs *client, uint8_t c);

// Parser functions to requests read
static bool parse_auth_version(client_hotdogs *client, uint8_t c);
static bool parse_auth_ulen(client_hotdogs *client, uint8_t c);
static bool parse_auth_username(client_hotdogs *client, uint8_t c);
static bool parse_auth_plen(client_hotdogs *client, uint8_t c);
static bool parse_auth_password(client_hotdogs *client, uint8_t c);

// Prepare responses
static void prepare_request_header(client_hotdogs *client, uint8_t* buffer);
static bool prepare_auth_response(client_hotdogs *client);
static bool prepare_request_response(client_hotdogs *client);
static bool prepare_retr_response(client_hotdogs *client);
static bool prepare_metrics_response(client_hotdogs *client);
static bool prepare_users_response(client_hotdogs *client);
static bool prepare_logs_response(client_hotdogs *client);
static bool prepare_mod_response(client_hotdogs *client);

static void execute_mod_actions(client_hotdogs *client);

// States definition
static const struct state_definition hotdogs_state_definitions[] = {
    {
        .state = HOTDOGS_AUTH,
        .on_read_ready = hotdogs_auth_read,
        .on_write_ready = NULL,
        .on_block_ready = NULL,
    },
    {
        .state = HOTDOGS_AUTH_RESPONSE, 
        .on_read_ready = NULL,
        .on_write_ready = hotdogs_auth_response,
        .on_block_ready = NULL,
    },
    {
        .state = HOTDOGS_REQUEST,
        .on_read_ready = hotdogs_request_read,
        .on_write_ready = NULL,
        .on_block_ready = NULL,
    },
    {
        .state = HOTDOGS_RESPONSE,
        .on_read_ready = NULL,
        .on_write_ready = hotdogs_response_write,
        .on_block_ready = NULL,
    },
    {
        .state = HOTDOGS_DONE,
        .on_read_ready = hotdogs_done_handler,    
        .on_write_ready = hotdogs_done_handler,   
        .on_block_ready = NULL,
    },
    {
        .state = HOTDOGS_ERROR,
        .on_read_ready = hotdogs_error_handler,   
        .on_write_ready = hotdogs_error_handler,  
        .on_block_ready = NULL,
    }
};

const struct state_definition * get_hotdogs_states(void) {
    return hotdogs_state_definitions;
}

// Manage the authentication read
static unsigned hotdogs_auth_read(struct selector_key *key) {
    client_hotdogs *client = (client_hotdogs *)key->data;

    // Read data from the socket into the read buffer
    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&client->read_buffer, &count);
    ssize_t len = recv(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    
    if (len == 0) {
        return HOTDOGS_DONE;
    }

    if (len < 0) {
        return HOTDOGS_ERROR;
    }
    
    buffer_write_adv(&client->read_buffer, len);
    
    // Proccess the read buffer with the parser
    bool auth_read_complete = false;
    while (buffer_can_read(&client->read_buffer) && !auth_read_complete) {
        uint8_t c = buffer_read(&client->read_buffer);
        switch (client->auth_parser.current_parse_state) {
            case HOTDOGS_PARSE_VERSION:
                auth_read_complete = parse_auth_version(client, c);
                break;
            case HOTDOGS_PARSE_ULEN:
                auth_read_complete = parse_auth_ulen(client, c);
                break;
            case HOTDOGS_PARSE_USERNAME:
                auth_read_complete = parse_auth_username(client, c);
                break;
            case HOTDOGS_PARSE_PLEN:
                auth_read_complete = parse_auth_plen(client, c);
                break;
            case HOTDOGS_PARSE_PASSWORD:
                auth_read_complete = parse_auth_password(client, c);
                break;
            case HOTDOGS_PARSE_DONE:
                // If we reach this state, it means we have read all the authentication data
                auth_read_complete = true; // Authentication data read complete
                break;
            default:
            ;
        }
    }

    if (auth_read_complete) {
        if (client->auth_parser.current_parse_state == HOTDOGS_PARSE_DONE) {
            if (authenticate_user(client->auth_parser.username, client->auth_parser.password) != 0) {
                memset(client->username, 0, sizeof(client->username));
                client->authenticated = UNDERCOOKED; // Invalid credentials
            } else {
                client->authenticated = AUTH_SUCCESS; // Authentication successful
            }
        }

        memset(&client->auth_parser, 0, sizeof(client->auth_parser));

        if (prepare_auth_response(client) == false) {
            return HOTDOGS_ERROR;
        }  

        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return HOTDOGS_ERROR;
        }
    
        return HOTDOGS_AUTH_RESPONSE;
    }
    return HOTDOGS_AUTH; // Continue reading authentication data
}

// Manage the authentication response
static unsigned hotdogs_auth_response(struct selector_key *key) {
    client_hotdogs *client = (client_hotdogs *)key->data;

    // Send client auth
    size_t count;
    uint8_t *bufptr = buffer_read_ptr(&client->write_buffer, &count);
    ssize_t len = send(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    
    if (len <= 0) {
        return HOTDOGS_ERROR;
    }
    
    buffer_read_adv(&client->write_buffer, len);
    
    // Verify if the write buffer is empty
    if (!buffer_can_read(&client->write_buffer)) {
        // If the write buffer is empty, we can switch to the next state
        if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            return HOTDOGS_ERROR;
        }

        if (client->authenticated == AUTH_SUCCESS) {
            log_hotdogs_access(client->username);
            return HOTDOGS_REQUEST;    // AUTH_SUCCESS then switch to request state
        } else {
            return HOTDOGS_AUTH;        // AUTH_FAILED then switch back to auth state
        }
    }
    
    return HOTDOGS_AUTH_RESPONSE; 
}

// Manage the request for METHOD or OPTIONS
static unsigned hotdogs_request_read(struct selector_key *key) {
    client_hotdogs *client = (client_hotdogs *)key->data;

    // Read data from the socket into the read buffer
    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&client->read_buffer, &count);
    ssize_t len = recv(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    
    if(len == 0) {
        return HOTDOGS_DONE;
    }

    if (len < 0) {
        return HOTDOGS_ERROR;
    }
    
    buffer_write_adv(&client->read_buffer, len);

    bool request_complete = false;
    while (buffer_can_read(&client->read_buffer) && !request_complete) {
        uint8_t c = buffer_read(&client->read_buffer);
        switch (client->request_parser.current_parse_state) {
            case HOTDOGS_PARSE_METHOD:
                request_complete = parse_request_method(client, c);
                break;
            case HOTDOGS_PARSE_OPTIONS:
                request_complete = parse_request_options(client, c);
                break;
            case HOTDOGS_PARSE_NEWBUFFSIZE:
                request_complete = parse_request_bufsize(client, c);
                break;
            case HOTDOGS_PARSE_ULEN:
                request_complete = parse_request_ulen(client, c);
                break;
            case HOTDOGS_PARSE_USERNAME:
                request_complete = parse_request_username(client, c);
                break;
            case HOTDOGS_PARSE_PLEN:
                request_complete = parse_request_plen(client, c);
                break;
            case HOTDOGS_PARSE_PASSWORD:
                request_complete = parse_request_password(client, c);
                break;
            default:
                break;
        }
        if (request_complete) {
            break;
        }
    }

    if (request_complete) {
        if (prepare_request_response(client) == false) {
            return HOTDOGS_ERROR;
        }

        // Cambiar a modo escritura para generar respuesta
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return HOTDOGS_ERROR;
        }
        
        // Resetear parser para próximo request
        client->request_parser.current_parse_state = HOTDOGS_PARSE_METHOD;
        
        return HOTDOGS_RESPONSE;
    }
    
    return HOTDOGS_REQUEST;
}

// Manage the response write
static unsigned hotdogs_response_write(struct selector_key *key) {
    client_hotdogs *client = (client_hotdogs *)key->data;

    // Send response to the client
    size_t count;
    uint8_t *bufptr = buffer_read_ptr(&client->write_buffer, &count);
    
    if (count == 0) {
        return HOTDOGS_ERROR;
    }
    
    ssize_t len = send(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    
    if (len <= 0) {
        return HOTDOGS_ERROR;
    }
    
    buffer_read_adv(&client->write_buffer, len);
    
    // Verify if was send
    if (!buffer_can_read(&client->write_buffer)) {
        
        // Change to read 
        if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            return HOTDOGS_ERROR;
        }

        return HOTDOGS_REQUEST; 
    }
    
    return HOTDOGS_RESPONSE; // Keep sending
}

static unsigned hotdogs_done_handler(struct selector_key *key) {
    close_hotdogs_connection(key);
    return HOTDOGS_DONE;
}

static unsigned hotdogs_error_handler(struct selector_key *key) {
    add_failed_connection();
    close_hotdogs_connection(key);
    return HOTDOGS_ERROR;
}

void clear_hotdogs_client(client_hotdogs * client){
    buffer_reset(&client->read_buffer);
    buffer_reset(&client->write_buffer);
    
    if (client->raw_buffer_a) {
        free(client->raw_buffer_a);
        client->raw_buffer_a = NULL;
    }
    
    if (client->raw_buffer_b) {
        free(client->raw_buffer_b);
        client->raw_buffer_b = NULL;
    }

    free(client);
}


void close_hotdogs_connection(struct selector_key *key) {
    if (key == NULL || key->data == NULL) {
        return;
    }

    client_hotdogs *client = (client_hotdogs *)key->data;

    if (client->dont_close)
        return;

    client->dont_close = true;

    if (client->client_socket != -1) {
        selector_unregister_fd(key->s, client->client_socket);
        close(client->client_socket);
        client->client_socket = -1; // Mark as closed
    }


    buffer_reset(&client->read_buffer);
    buffer_reset(&client->write_buffer);
    
    if (client->raw_buffer_a) {
        free(client->raw_buffer_a);
        client->raw_buffer_a = NULL;
    }
    
    if (client->raw_buffer_b) {
        free(client->raw_buffer_b);
        client->raw_buffer_b = NULL;
    }

    key->data = NULL;

    free(client);
}

void init_hotdogs_client(client_hotdogs *client, int client_socket) {
    if (client == NULL) {
        fprintf(stderr, "Error: client is NULL\n");
        return;
    }

    memset(client, 0, sizeof(client_hotdogs));
    
    client->client_socket = client_socket;
    client->dont_close = false;
    
    // Initialize buffers
    client->raw_buffer_a = malloc(MAX_HOTDOGS_BUFFER_SIZE);
    client->raw_buffer_b = malloc(MAX_HOTDOGS_BUFFER_SIZE);
    
    buffer_init(&client->read_buffer, MAX_HOTDOGS_BUFFER_SIZE, client->raw_buffer_a);
    buffer_init(&client->write_buffer, MAX_HOTDOGS_BUFFER_SIZE, client->raw_buffer_b);
    
    // Initialize state machine
    client->stm.initial = HOTDOGS_AUTH;
    client->stm.max_state = HOTDOGS_ERROR;
    client->stm.states = get_hotdogs_states();

    client->auth_parser.current_parse_state = HOTDOGS_PARSE_VERSION;
    client->request_parser.current_parse_state = HOTDOGS_PARSE_METHOD;
    
    stm_init(&client->stm);
}



// Prepare request responses
static void prepare_request_header(client_hotdogs *client, uint8_t* buffer){
    if (client == NULL || buffer == NULL) {
        return; // Invalid parameters
    }

    // Respuesta MOD: [METHOD][OPTION][STATUS]
    buffer[0] = (uint8_t)client->current_method;
    buffer[1] = (uint8_t)client->current_option;
    buffer[2] = (uint8_t)client->current_response_status;
}

static bool prepare_auth_response(client_hotdogs *client) {
    // Reset write buffer
    buffer_reset(&client->write_buffer);
    
    size_t size = MAX_HOTDOGS_BUFFER_SIZE;
    uint8_t *write_buffer_ptr = buffer_write_ptr(&client->write_buffer, &size);
    
    if (size < 2) {
        return false; // Not enough space in the buffer
    }
    
    write_buffer_ptr[0] = VERSION;                         
    write_buffer_ptr[1] = (uint8_t) client->authenticated; // COOK_STATUS
    
    buffer_write_adv(&client->write_buffer, 2);
    
    return true;
}

static bool prepare_request_response(client_hotdogs *client) {
    // Reset write buffer
    buffer_reset(&client->write_buffer);
    
    if (client->current_response_status == SUCCESS_RESPONSE){
        if (client->current_method == RETR) {
            return prepare_retr_response(client);
        } else if (client->current_method == MOD) {
            return prepare_mod_response(client);
        }
        return false;
    }

    // For other status, we just prepare a simple error response
    size_t size;
    uint8_t *buf = buffer_write_ptr(&client->write_buffer, &size);

    if (size < BASE_RESPONSE_LEN) {
        return false; // Not enough space in the buffer
    }
    
    // Header (3 bytes)
    prepare_request_header(client, buf);
    
    return true;
}

static bool prepare_retr_response(client_hotdogs *client) {
    switch (client->current_option) {
        case METRICS:
            return prepare_metrics_response(client);
        case LIST_USERS:
            return prepare_users_response(client);
        case LIST_LOGS:
            return prepare_logs_response(client);
        default:
            return false;
    }
}

static bool prepare_metrics_response(client_hotdogs *client) {
    log_hotdogs_action(client->username, "LIST METRICS", "-");
    size_t size;
    uint8_t *buf = buffer_write_ptr(&client->write_buffer, &size);
    
    // Respuesta METRICS: [METHOD][OPTION][STATUS][CONN-HS][CONN-CURR][CONN-FAIL][BYTES-TSF]
    // Total: 3 + 16 = 19 bytes
    if (size < BASE_RESPONSE_LEN + METRICS_RESPONSE_LEN) {
        return false;
    }
    
    // Header (3 bytes)
    prepare_request_header(client, buf);
    
    // Obtener métricas reales del servidor
    uint32_t historic_conn = (uint32_t)get_historic_connections();
    uint32_t current_conn = (uint32_t)get_current_connections();
    uint32_t fail_conn = (uint32_t) get_failed_connections();  
    uint32_t bytes_transf = (uint32_t)get_transfered_bytes();
    
    // Escribir métricas en big-endian (4 bytes cada uno)
    // CONN-HS (historic connections)
    buf[3] = (historic_conn >> 24) & 0xFF;
    buf[4] = (historic_conn >> 16) & 0xFF;
    buf[5] = (historic_conn >> 8) & 0xFF;
    buf[6] = historic_conn & 0xFF;
    
    // CONN-CURR (current connections)
    buf[7] = (current_conn >> 24) & 0xFF;
    buf[8] = (current_conn >> 16) & 0xFF;
    buf[9] = (current_conn >> 8) & 0xFF;
    buf[10] = current_conn & 0xFF;
    
    // CONN-FAIL (failed connections)
    buf[11] = (fail_conn >> 24) & 0xFF;
    buf[12] = (fail_conn >> 16) & 0xFF;
    buf[13] = (fail_conn >> 8) & 0xFF;
    buf[14] = fail_conn & 0xFF;
    
    // BYTES-TSF (bytes transferred)
    buf[15] = (bytes_transf >> 24) & 0xFF;
    buf[16] = (bytes_transf >> 16) & 0xFF;
    buf[17] = (bytes_transf >> 8) & 0xFF;
    buf[18] = bytes_transf & 0xFF;
    
    buffer_write_adv(&client->write_buffer, BASE_RESPONSE_LEN + METRICS_RESPONSE_LEN);
    
    return true;
}

static bool prepare_users_response(client_hotdogs *client) {
    log_hotdogs_action(client->username, "LIST USERS", "");
    size_t size;
    uint8_t *buf = buffer_write_ptr(&client->write_buffer, &size);
    
    // Respuesta USERS: [METHOD][OPTION][STATUS][DATA_LEN][DATA]
    if (size < BASE_RESPONSE_LEN + DATA_LEN) {
        return false;
    }
    
    // Header (3 bytes)
    prepare_request_header(client, buf);

    uint64_t transfered_bytes = BASE_RESPONSE_LEN;
    
    if (client->current_response_status == SUCCESS_RESPONSE) {
        char users_data[MAX_DATA_SIZE];        
        users_data[0] = '\0';

        uint16_t user_data_len = get_users_separator(users_data, MAX_DATA_SIZE, SEPARATOR, SEPARATOR_SIZE);

        if (size < BASE_RESPONSE_LEN + DATA_LEN + user_data_len) {
            return false;
        }

        buf[3] = (user_data_len >> 8) & 0xFF;
        buf[4] = user_data_len & 0xFF;
        
        // DATA
        memcpy(&buf[5], users_data, user_data_len);

        transfered_bytes += DATA_LEN + user_data_len;
    }
    
    buffer_write_adv(&client->write_buffer, transfered_bytes);
    return true;
}

static bool prepare_logs_response(client_hotdogs *client) {
    log_hotdogs_action(client->username, "LIST LOGS", "");
    size_t size;
    uint8_t *buf = buffer_write_ptr(&client->write_buffer, &size);
    
    // Respuesta LOGS: [METHOD][OPTION][STATUS][DATA_LEN][DATA]
    if (size < BASE_RESPONSE_LEN + DATA_LEN) {
        return false;
    }

    // Header (3 bytes)
    prepare_request_header(client, buf);
    
    // Preparar datos de logs (formato simple)
    char log_data[MAX_DATA_SIZE];
    uint16_t data_len =  get_logs_separator(log_data, MAX_DATA_SIZE, SEPARATOR, SEPARATOR_SIZE);

    
    // Verificar espacio total
    if (size < BASE_RESPONSE_LEN + DATA_LEN + data_len) {
        return false;
    }
    
    // DATA_LEN (2 bytes, big-endian)
    buf[3] = (data_len >> 8) & 0xFF;
    buf[4] = data_len & 0xFF;
    
    // DATA
    memcpy(&buf[5], log_data, data_len);
    
    buffer_write_adv(&client->write_buffer, BASE_RESPONSE_LEN + DATA_LEN + data_len);
    
    return true;
}

static bool prepare_mod_response(client_hotdogs *client) {
    size_t size;
    uint8_t *buf = buffer_write_ptr(&client->write_buffer, &size);
    
    if (size < BASE_RESPONSE_LEN) {
        return false;
    }
    
    execute_mod_actions(client);

    // Respuesta MOD: [METHOD][OPTION][STATUS]
    prepare_request_header(client, buf);
    
    buffer_write_adv(&client->write_buffer, BASE_RESPONSE_LEN);
    
    return true;
}

static void execute_mod_actions(client_hotdogs *client) {
    char values[128];
    switch (client->current_option) {
        case BUF_SIZE:
            socks_set_buffer_size(client->request_parser.new_buffer_size);
            snprintf(values, sizeof(values), "%u", client->request_parser.new_buffer_size);
            log_hotdogs_action(client->username, "SET BUF_SIZE", values);
            break;
        case ADD_USER:
            add_user(client->request_parser.username, client->request_parser.password); 
            snprintf(values, sizeof(values), "%s, *****", client->request_parser.username);
            log_hotdogs_action(client->username, "ADD USER", values);
            break;
        case REMOVE_USER:
            remove_user(client->request_parser.username);
            snprintf(values, sizeof(values), "%s", client->request_parser.username);
            log_hotdogs_action(client->username, "REMOVE USER", values);
            break;
    }
}



// Parse requests
static bool parse_auth_version(client_hotdogs *client, uint8_t c) {
    if (c != VERSION) {
        client->authenticated = BURNT; // Invalid version
        return true;
    }
    client->auth_parser.current_parse_state = HOTDOGS_PARSE_ULEN; // Next state
    return false;
}

static bool parse_auth_ulen(client_hotdogs *client, uint8_t c) {
    if (c < 1 || c > MAX_UNAME_LEN) {
        client->auth_parser.current_parse_state = HOTDOGS_PARSE_ERROR;
        client->authenticated = WHO_LET_BRO_COOK; // Invalid username length
        return true;
    }

    client->auth_parser.username_len = c;
    client->auth_parser.username_remaining = c;
    client->auth_parser.current_parse_state = HOTDOGS_PARSE_USERNAME; // Next state
    return false;
}

static bool parse_auth_username(client_hotdogs *client, uint8_t c) {
    if (client->auth_parser.username_remaining > 0) {
        client->username[client->auth_parser.username_len - client->auth_parser.username_remaining] = c;
        client->auth_parser.username[client->auth_parser.username_len - client->auth_parser.username_remaining] = c;
        client->auth_parser.username_remaining--;  
        if (client->auth_parser.username_remaining == 0) {
            client->auth_parser.username[client->auth_parser.username_len] = '\0'; // Null-terminate the username
            client->auth_parser.current_parse_state = HOTDOGS_PARSE_PLEN; // Next state   
        } 
    } else {
        client->auth_parser.current_parse_state = HOTDOGS_PARSE_ERROR;
        client->authenticated = WHO_LET_BRO_COOK; // Invalid username length
        return true; // Error
    }
    return false;
}

static bool parse_auth_plen(client_hotdogs *client, uint8_t c) {
    if (c < 1 || c > MAX_PASS_LEN) {
        client->auth_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid password length
        client->authenticated = WHO_LET_BRO_COOK; // Invalid password length
        return true;
    }
    
    client->auth_parser.password_len = c;
    client->auth_parser.password_remaining = c;

    client->auth_parser.current_parse_state = HOTDOGS_PARSE_PASSWORD; // Next state
    return false;
}

static bool parse_auth_password(client_hotdogs *client, uint8_t c) {
    if (client->auth_parser.password_remaining > 0) {
        client->auth_parser.password[client->auth_parser.password_len - client->auth_parser.password_remaining] = c;
        client->auth_parser.password_remaining--;
        if (client->auth_parser.password_remaining == 0) {
            client->auth_parser.password[client->auth_parser.password_len] = '\0'; // Null-terminate the password
            client->auth_parser.current_parse_state = HOTDOGS_PARSE_DONE; // Next state
            return true;
        }
    } else {
        client->auth_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid password length
        client->authenticated = WHO_LET_BRO_COOK; // Invalid password length
        return true; // Error
    }
    return false;
}

static bool parse_request_method(client_hotdogs *client, uint8_t c){
    if (c != RETR && c != MOD) {
        client->request_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid method
        client->current_response_status = NO_BUN_FOUND; // Set response status
        return true; // Error
    }
    
    client->current_method = (ReqMethod) c;
    client->request_parser.current_method = (ReqMethod) c;
    client->request_parser.current_parse_state = HOTDOGS_PARSE_OPTIONS;
    
    return false; // No complete yet
}

static bool parse_request_options(client_hotdogs *client, uint8_t c){
    if (client->request_parser.current_method == RETR) {
        return parse_request_retr_options(client, c);
    } else if (client->request_parser.current_method == MOD) {
        return parse_request_mod_options(client, c);
    } else {
        client->request_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid method
        client->current_response_status = BAD_TOPPING;
        return true; // Error
    }
}

static bool parse_request_retr_options(client_hotdogs *client, uint8_t c){
    switch (c) {
        case  METRICS:
            break;
        case LIST_USERS:
            break;
        case LIST_LOGS:
            break;
        default:
            client->request_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid option
            client->current_response_status = BAD_TOPPING; // Set response status
            return true; // Error
            break;
        }
    
    client->current_option = c;
    client->request_parser.current_option = c;

    client->request_parser.current_parse_state = HOTDOGS_PARSE_DONE; // No more options
    client->current_response_status = SUCCESS_RESPONSE; // Set response status
    
    return true; // Complete
}

static bool parse_request_mod_options(client_hotdogs *client, uint8_t c){
    switch (c) {
        case BUF_SIZE:
            client->request_parser.buffer_size_bytes_remaining = BUFFER_SIZE_BYTES_SOCKS5;
            client->request_parser.current_parse_state = HOTDOGS_PARSE_NEWBUFFSIZE; // Next state
            break;
        case ADD_USER:
            client->request_parser.current_parse_state = HOTDOGS_PARSE_ULEN; // Next state
            break;
        // TODO: check for timeout
        case REMOVE_USER:
            client->request_parser.current_parse_state = HOTDOGS_PARSE_ULEN; // Next state
            break;
        default:
            client->request_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid option
            client->current_response_status = BAD_TOPPING; // Set response status
            return true; // Error
    }
    
    client->current_option = c;
    client->request_parser.current_option = c;
    
    return false; // No complete yet
}

static bool parse_request_bufsize(client_hotdogs *client, uint8_t c){
    switch(client->request_parser.buffer_size_bytes_remaining) {
        case 2: 
            // Primer byte (MSB - Most Significant Byte)
            client->request_parser.new_buffer_size = (uint16_t)c << 8;
            client->request_parser.buffer_size_bytes_remaining--;
            return false; // No complete yet
            break;
            
        case 1:
            // Segundo byte (LSB - Least Significant Byte)
            client->request_parser.new_buffer_size |= (uint16_t)c;
            client->request_parser.buffer_size_bytes_remaining--;

            
            // Validar que el buffer size sea razonable
            if (client->request_parser.new_buffer_size <= 0 || 
                client->request_parser.new_buffer_size > MAX_SOCKS5_BUFFER_SIZE) {

                client->request_parser.current_parse_state = HOTDOGS_PARSE_ERROR;
                client->current_response_status = WHO_LET_BRO_COOK_RESPONSE;

                return true; // Error
            }
            
            client->request_parser.current_parse_state = HOTDOGS_PARSE_DONE;
            client->current_response_status = SUCCESS_RESPONSE; // Set response status
            return true; // Complete
        default:
            client->request_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid buffer size
            client->current_response_status = WHO_LET_BRO_COOK_RESPONSE;
            return true; // Error
    }
}

static bool parse_request_ulen(client_hotdogs *client, uint8_t c){
    if (c < 1 || c > MAX_UNAME_LEN) {
        client->request_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid username length
        client->current_response_status = WHO_LET_BRO_COOK_RESPONSE; // Set response status
        return true; // Error
    }

    client->request_parser.username_len = c;
    client->request_parser.username_remaining = c;
    client->request_parser.current_parse_state = HOTDOGS_PARSE_USERNAME; // Next state
    
    return false; // No complete yet
}

static bool parse_request_username(client_hotdogs *client, uint8_t c){
    if (client->request_parser.username_remaining > 0) {
        client->request_parser.username[client->request_parser.username_len - client->request_parser.username_remaining] = c;
        client->request_parser.username_remaining--;
        
        if (client->request_parser.username_remaining == 0 ) {
            client->request_parser.username[client->request_parser.username_len] = '\0'; // Null-terminate the username
            if (client->request_parser.current_option == ADD_USER) {
                client->request_parser.current_parse_state = HOTDOGS_PARSE_PLEN; // Next state for password length
            } else if (client->request_parser.current_option == REMOVE_USER) {
                client->request_parser.current_parse_state = HOTDOGS_PARSE_DONE; // No more options
                return true; // Complete
            } else {
                client->request_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid option
            }
            return false; // No complete yet
        }
    } else {
        client->request_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid username length
        client->current_response_status = WHO_LET_BRO_COOK_RESPONSE;
        return true; // Error
    }
    
    return false; // No complete yet
}

static bool parse_request_plen(client_hotdogs *client, uint8_t c){
    if (c < 1 || c > MAX_PASS_LEN) {
        client->request_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid password length
        client->current_response_status = WHO_LET_BRO_COOK_RESPONSE;
        return true; // Error
    }

    client->request_parser.password_len = c;
    client->request_parser.password_remaining = c;
    client->request_parser.current_parse_state = HOTDOGS_PARSE_PASSWORD; // Next state
    
    return false; // No complete yet

}

static bool parse_request_password(client_hotdogs *client, uint8_t c){
    if (client->request_parser.password_remaining > 0) {
        client->request_parser.password[client->request_parser.password_len - client->request_parser.password_remaining] = c;
        client->request_parser.password_remaining--;
        
        if (client->request_parser.password_remaining == 0) {
            client->request_parser.password[client->request_parser.password_len] = '\0'; // Null-terminate the password
            client->request_parser.current_parse_state = HOTDOGS_PARSE_DONE; // Next state
            return true; // Complete
        }
    } else {
        client->request_parser.current_parse_state = HOTDOGS_PARSE_ERROR; // Invalid password length
        client->current_response_status = WHO_LET_BRO_COOK_RESPONSE; // Set response status
        return true; // Error
    }
    
    return false; // No complete yet
}
