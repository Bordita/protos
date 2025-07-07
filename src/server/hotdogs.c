#include "./includes/hotdogs.h"

#include "../shared/metrics.h"
#include "../shared/auth.h"
#include "../shared/includes/logger.h"
#include "../shared/parser.h"
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

// Prepare responses
static bool prepare_request_response(client_hotdogs *client);
static bool prepare_retr_response(client_hotdogs *client);
static bool prepare_metrics_response(client_hotdogs *client);
static bool prepare_users_response(client_hotdogs *client);
static bool prepare_logs_response(client_hotdogs *client);
static bool prepare_mod_response(client_hotdogs *client);

static void execute_mod_actions(client_hotdogs *client);


// Prepare the response for the request
static bool prepare_request_response(client_hotdogs *client);

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
    
    printf("Reading auth....\n");

    // Read data from the socket into the read buffer
    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&client->read_buffer, &count);
    ssize_t len = recv(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    
    if (len <= 0) {
        return HOTDOGS_ERROR;
    }
    
    buffer_write_adv(&client->read_buffer, len);
    
    // Proccess the read buffer with the parser
    bool auth_read_complete = false;
    while (buffer_can_read(&client->read_buffer) && !auth_read_complete) {
        uint8_t c = buffer_read(&client->read_buffer);
        switch (client->auth_parser.current_parse_state) {
            case HOTDOGS_PARSE_VERSION:
                if (c != VERSION) {
                    client->authenticated = BURNT; // Invalid version
                    return HOTDOGS_AUTH_RESPONSE;
                }
                client->auth_parser.current_parse_state = HOTDOGS_PARSE_ULEN; // Next state
                break;
            case HOTDOGS_PARSE_ULEN:
                if (c < 1 || c > MAX_UNAME_LEN) {
                    client->authenticated = WHO_LET_BRO_COOK; // Invalid password length
                    return HOTDOGS_AUTH_RESPONSE;
                }

                client->auth_parser.username_len = c;
                client->auth_parser.username_remaining = c;
                client->auth_parser.current_parse_state = HOTDOGS_PARSE_USERNAME; // Next state
                break;
            case HOTDOGS_PARSE_USERNAME:

                if (client->auth_parser.username_remaining > 0) {
                    client->username[client->auth_parser.username_len - client->auth_parser.username_remaining] = c;
                    client->auth_parser.username[client->auth_parser.username_len - client->auth_parser.username_remaining] = c;
                    client->auth_parser.username_remaining--;  
                    if (client->auth_parser.username_remaining == 0) {
                        client->auth_parser.username[client->auth_parser.username_len] = '\0'; // Null-terminate the username
                        client->auth_parser.current_parse_state = HOTDOGS_PARSE_PLEN; // Next state   
                    } 
                }  
                break;
            case HOTDOGS_PARSE_PLEN:
                if (c < 1 || c > MAX_PASS_LEN) {
                    client->authenticated = WHO_LET_BRO_COOK; // Invalid password length
                    return HOTDOGS_AUTH_RESPONSE;
                }
                
                client->auth_parser.password_len = c;
                client->auth_parser.password_remaining = c;
            
                client->auth_parser.current_parse_state = HOTDOGS_PARSE_PASSWORD; // Next state
                break;
            case HOTDOGS_PARSE_PASSWORD:
                if (client->auth_parser.password_remaining > 0) {
                    client->auth_parser.password[client->auth_parser.password_len - client->auth_parser.password_remaining] = c;
                    client->auth_parser.password_remaining--;
                    if (client->auth_parser.password_remaining == 0) {
                        client->auth_parser.password[client->auth_parser.password_len] = '\0'; // Null-terminate the password
                        client->auth_parser.current_parse_state = HOTDOGS_PARSE_DONE; // Next state
                        auth_read_complete = true; // Authentication data read complete
                    }
                } 
                break;
            case HOTDOGS_PARSE_DONE:
                // If we reach this state, it means we have read all the authentication data
                auth_read_complete = true; // Authentication data read complete
                break;
        }
    }

    // Cannot parse properly
    if (auth_read_complete) {
        if (authenticate_user(client->auth_parser.username, client->auth_parser.password) != 0) {
            memset(client->username, 0, sizeof(client->username));
            memset(client->auth_parser.username, 0, sizeof(client->auth_parser.username));
            memset(client->auth_parser.password, 0, sizeof(client->auth_parser.password));
            client->authenticated = UNDERCOOKED; // Invalid credentials
        } else {
            memset(client->auth_parser.username, 0, sizeof(client->auth_parser.username));
            memset(client->auth_parser.password, 0, sizeof(client->auth_parser.password));

            client->authenticated = AUTH_SUCCESS; // Authentication successful
        }

        size_t size = MAX_HOTDOGS_BUFFER_SIZE;
        uint8_t *write_buffer_ptr = buffer_write_ptr(&client->write_buffer, &size);
        
        if (size < 2) {
            return HOTDOGS_ERROR; // Not enough space in the buffer
        }
        
        write_buffer_ptr[0] = VERSION;                         
        write_buffer_ptr[1] = (uint8_t) client->authenticated; // COOK_STATUS
        
        buffer_write_adv(&client->write_buffer, 2);  


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

    printf("Auth response....\n");

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

    printf("Reading request.....\n");

    // Read data from the socket into the read buffer
    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&client->read_buffer, &count);
    ssize_t len = recv(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    
    if(len == 0) {
        printf("HOT DONE\n");
        return HOTDOGS_DONE;
    }

    if (len < 0) {
        printf("HOT ERROR\n");
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

    printf("Sending response....\n");

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
    printf("Sent %zd bytes successfully\n", len);
    
    // Verify if was send
    if (!buffer_can_read(&client->write_buffer)) {
        printf("Response sent completely\n");
        
        // Change to read 
        if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            return HOTDOGS_ERROR;
        }

        return HOTDOGS_REQUEST; 
    }
    
    return HOTDOGS_RESPONSE; // Keep sending
}

static unsigned hotdogs_done_handler(struct selector_key *key) {
    printf("HotDogs connection completed successfully\n");
    close_hotdogs_connection(key);
    return HOTDOGS_DONE;
}

static unsigned hotdogs_error_handler(struct selector_key *key) {
    printf("HotDogs connection ended with error\n");
    close_hotdogs_connection(key);
    return HOTDOGS_ERROR;
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
    
    remove_hdp_current_connection();
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



// Prepare responses
static bool prepare_request_response(client_hotdogs *client) {
    // Reset write buffer
    buffer_reset(&client->write_buffer);
    
    if (client->current_method == RETR) {
        return prepare_retr_response(client);
    } else if (client->current_method == MOD) {
        return prepare_mod_response(client);
    }
    
    return false;
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
    size_t size;
    uint8_t *buf = buffer_write_ptr(&client->write_buffer, &size);
    
    // Respuesta METRICS: [METHOD][OPTION][STATUS][CONN-HS][CONN-CURR][CONN-FAIL][BYTES-TSF]
    // Total: 3 + 16 = 19 bytes
    if (size < BASE_RESPONSE_LEN + METRICS_RESPONSE_LEN) {
        return false;
    }
    
    // Header (3 bytes)
    buf[0] = (uint8_t)RETR;                    // METHOD = 0
    buf[1] = (uint8_t)METRICS;                 // OPTION = 0  
    buf[2] = (uint8_t)SUCCESS_RESPONSE;        // STATUS = 0
    
    // Obtener métricas reales del servidor
    uint32_t historic_conn = (uint32_t)get_historic_connections();
    uint32_t current_conn = (uint32_t)get_current_connections();
    uint32_t fail_conn = 0;  // TODO: implementar contador de fallos
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
    size_t size;
    uint8_t *buf = buffer_write_ptr(&client->write_buffer, &size);
    
    // Respuesta USERS: [METHOD][OPTION][STATUS][DATA_LEN][DATA]
    if (size < BASE_RESPONSE_LEN + DATA_LEN) {
        return false;
    }
    
    // Header (3 bytes)
    buf[0] = (uint8_t)RETR;
    buf[1] = (uint8_t)LIST_USERS;
    buf[2] = (uint8_t)client->current_response_status;
    
    if (client->current_response_status == SUCCESS_RESPONSE) {
        char users_data[2048];        
        users_data[0] = '\0';

        uint16_t data_len = get_users_separator(users_data, sizeof(users_data), USERS_SEPARATOR, USERS_SEPARATOR_SIZE);

        if (size < BASE_RESPONSE_LEN + DATA_LEN + data_len) {
            return false;
        }

        buf[3] = (data_len >> 8) & 0xFF;
        buf[4] = data_len & 0xFF;
        
        // DATA
        memcpy(&buf[5], users_data, data_len);
        
        add_transfered_bytes(BASE_RESPONSE_LEN + DATA_LEN + data_len);
        buffer_write_adv(&client->write_buffer, BASE_RESPONSE_LEN + DATA_LEN + data_len);
    } else {
        add_transfered_bytes(BASE_RESPONSE_LEN);
        buffer_write_adv(&client->write_buffer, BASE_RESPONSE_LEN);
    }

    return true;
}

static bool prepare_logs_response(client_hotdogs *client) {
    size_t size;
    uint8_t *buf = buffer_write_ptr(&client->write_buffer, &size);
    
    // Respuesta LOGS: [METHOD][OPTION][STATUS][DATA_LEN][DATA]
    if (size < BASE_RESPONSE_LEN + DATA_LEN) {
        return false;
    }
    //todo: implement
    // Header (3 bytes)
    buf[0] = (uint8_t)RETR;
    buf[1] = (uint8_t)LIST_LOGS;
    buf[2] = (uint8_t)SUCCESS_RESPONSE;
    
    // Preparar datos de logs (formato simple)
    char logs_data[] = "2024-01-01 10:00:00 - User connected\r2024-01-01 10:01:00 - User disconnected\r";
    uint16_t data_len = strlen(logs_data);
    
    // Verificar espacio total
    if (size < BASE_RESPONSE_LEN + DATA_LEN + data_len) {
        return false;
    }
    
    // DATA_LEN (2 bytes, big-endian)
    buf[3] = (data_len >> 8) & 0xFF;
    buf[4] = data_len & 0xFF;
    
    // DATA
    memcpy(&buf[5], logs_data, data_len);
    
    buffer_write_adv(&client->write_buffer, BASE_RESPONSE_LEN + DATA_LEN + data_len);
    
    printf("Prepared LOGS response: %d bytes of data\n", data_len);
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
    buf[0] = (uint8_t)MOD;
    buf[1] = (uint8_t)client->current_option;
    buf[2] = (uint8_t)SUCCESS_RESPONSE;
    
    add_transfered_bytes(BASE_RESPONSE_LEN);
    buffer_write_adv(&client->write_buffer, BASE_RESPONSE_LEN);
    
    printf("Prepared MOD response: Option=%d\n", client->current_option);
    return true;
}

static void execute_mod_actions(client_hotdogs *client) {
    switch (client->current_option) {
        case BUF_SIZE:
            socks_set_buffer_size(client->request_parser.new_buffer_size);
            break;
        case ADD_USER:
            add_user(client->request_parser.username, client->request_parser.password); 
            break;
        case REMOVE_USER:
            remove_user(client->request_parser.username);
            break;
    }
}


// Parse requests
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
        client->current_response_status = WHO_LET_BRO_COOK;
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
