#include "./includes/socks5.h"
#include "../shared/includes/buffer.h"
#include "../shared/includes/parser.h"
#include "../shared/includes/stm.h"
#include "../shared/includes/selector.h"
#include "../shared/includes/metrics.h"
#include "../shared/includes/logger.h"
#include "includes/greeting.h"
#include "includes/authentication.h"
#include "includes/request.h"
#include "includes/serverHandle.h"
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>


static void* request_resolv_thread(void * arg);
static socks5_states try_next_address(struct selector_key * key);

uint32_t buffer_size = MAX_SOCKS5_BUFFER_SIZE; 

void log_socks5_client_access(client_socks5 * client) {
    // Obtener IP y puerto del cliente
    char client_ipstr[INET6_ADDRSTRLEN];
    char destination_ipstr[INET6_ADDRSTRLEN];
    int client_port;
    int destination_port;

    if (client->client_addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&client->client_addr;
        inet_ntop(AF_INET, &s->sin_addr, client_ipstr, sizeof(client_ipstr));
        client_port = ntohs(s->sin_port);
    } else { // AF_INET6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client->client_addr;
        inet_ntop(AF_INET6, &s->sin6_addr, client_ipstr, sizeof(client_ipstr));
        client_port = ntohs(s->sin6_port);
    }

    if (client->destination_addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&client->destination_addr;
        inet_ntop(AF_INET, &s->sin_addr, destination_ipstr, sizeof(destination_ipstr));
        destination_port = ntohs(s->sin_port);
    } else { // AF_INET6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client->destination_addr;
        inet_ntop(AF_INET6, &s->sin6_addr, destination_ipstr, sizeof(destination_ipstr));
        destination_port = ntohs(s->sin6_port);
    }
    char * username = "anonymous";
    if(client->auth_info.authenticated) {
        username = client->auth_info.username;
    }
    log_access(username, client_ipstr, client_port, destination_ipstr, destination_port);
}

socks5_reply errno_to_socks5_reply(int err) {
    switch (err) {
        case ECONNREFUSED:
            return REP_CONNECTION_REFUSED;
        case ETIMEDOUT:
            return REP_HOST_UNREACHABLE;
        case ENETUNREACH:
            return REP_NETWORK_UNREACHABLE;
        case EHOSTUNREACH:
        case EADDRNOTAVAIL:
            return REP_HOST_UNREACHABLE;
        case EACCES:
            return REP_CONNECTION_NOT_ALLOWED;
        case EAFNOSUPPORT:
        case EINVAL:
            return REP_ADDRESS_TYPE_NOT_SUPPORTED;
        case ENOTSOCK:
            return REP_GENERAL_FAILURE;
        default:
            return REP_GENERAL_FAILURE;
    }
}


static inline void clear_parsing_state(client_socks5 *client) {
    parser_destroy(client->parser);
    memset(&client->parsing_state, 0, sizeof(client->parsing_state));
    client->parser = NULL;
}

static socks5_states connect_destination(struct selector_key * key){
    client_socks5 * client = (client_socks5 *)key->data;

   
    if (client->resolved_addr != NULL && client->resolved_addr_current != NULL) {
        client->destination_domain = client->resolved_addr_current->ai_family;
        client->destination_addr_len = client->resolved_addr_current->ai_addrlen;
        memcpy(&client->destination_addr, client->resolved_addr_current->ai_addr, client->resolved_addr_current->ai_addrlen);
    }

    client->destination_socket = socket(client->destination_domain, SOCK_STREAM, IPPROTO_TCP);
    if (client->destination_socket == -1) {
        printf("Error creando socket: %s\n", strerror(errno));
        return ERROR;
    }
    
    selector_status ret = selector_fd_set_nio(client->destination_socket);
    if (ret != SELECTOR_SUCCESS) {
        client->destination_socket = -1;
        close(client->destination_socket);
        return ERROR;
    }

    int connect_result = connect(client->destination_socket, (struct sockaddr *)&client->destination_addr, client->destination_addr_len);
    if(connect_result < 0 && errno != EINPROGRESS) {
        close(client->destination_socket);
        client->destination_socket = -1;  
        return try_next_address(key);
    }

    if (SELECTOR_SUCCESS != selector_set_interest(key->s, client->client_socket, OP_NOOP)) {
        client->destination_socket = -1;  
        close(client->destination_socket);
        return ERROR;
    }
    if (SELECTOR_SUCCESS != selector_register(key->s, client->destination_socket, get_connection_fd_handler(), OP_WRITE, client)) {
        close(client->destination_socket);
        client->destination_socket = -1;
        return ERROR;
    }
    client->connection_attempts++;
    return REQUEST_CONNECT;
}

static void greeting_read_init(unsigned state, struct selector_key * key){
    client_socks5 * client = (client_socks5 *)key->data;
    clear_parsing_state(client);
    client->parser = parser_init(parser_no_classes(), greeting_parser_definition());
}

static socks5_states greeting_read(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
 

    size_t count;
    uint8_t * bufptr = buffer_write_ptr(&client->read_buffer, &count);

    ssize_t len = recv(client->client_socket, bufptr, count, MSG_NOSIGNAL);

    if (len <= 0) {
        return ERROR;
    } else {
        buffer_write_adv(&client->read_buffer, len);
    }

    greeting_event_type event = parser_read(client, &client->read_buffer);
    if (event == GREETING_EVENT_DONE) {
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE) || generate_connection_response(&client->write_buffer,client->selected_method) == -1) {
            return ERROR;
        }
        return GREETING_WRITE;
    } else if(event == GREETING_EVENT_VERSION_ERROR){
        return ERROR;
    }
    return GREETING_READ;
}

static socks5_states greeting_write(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    size_t count;
    uint8_t * bufptr = buffer_read_ptr(&client->write_buffer, &count);
    ssize_t len = send(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len <= 0) {
        return ERROR;
    } else {
        buffer_read_adv(&client->write_buffer, len);
    }
    if (!buffer_can_read(&client->write_buffer)) {
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
            switch (client->selected_method) {
            case METHOD_NO_AUTHENTICATION_REQUIRED:
                return REQUEST_READ;
            case METHOD_USERNAME_PASSWORD:
                return AUTHENTICATION_READ;
            case METHOD_NO_ACCEPTABLE_METHODS:
                return ERROR;
            }
        }
        return ERROR;
    }
    return GREETING_WRITE;
}

static void authentication_read_init(unsigned state, struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    clear_parsing_state(client);
    client->parser = parser_init(parser_no_classes(), auth_parser_definition());
}

static socks5_states authentication_read(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    size_t count;
    uint8_t * bufptr = buffer_write_ptr(&client->read_buffer, &count);
    ssize_t len = recv(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len <= 0) {
        return ERROR;
    } else {
        buffer_write_adv(&client->read_buffer, len);
    }
    auth_event_type event = auth_parser_read(client, &client->read_buffer);
    if (event == AUTH_EVENT_DONE) {
        if (authenticate_credentials(client->auth_info) != AUTH_STATUS_SUCCESS) {
            client->auth_info.authenticated = false;
            if(generate_auth_response(&client->write_buffer, AUTH_STATUS_FAILURE) != 0) {
                return ERROR;
            }
            if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE)) {
                return ERROR;
            }
            return AUTHENTICATION_WRITE;
        }
        client->auth_info.authenticated = true;
        if (generate_auth_response(&client->write_buffer, AUTH_STATUS_SUCCESS) != 0) {
            return ERROR;
        }
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE)) {
            return ERROR;
        }
        return AUTHENTICATION_WRITE;
    } else if (event == AUTH_EVENT_ERROR) {
        return ERROR;
    } else if (event == AUTH_EVENT_VERSION_ERROR) {     
        return ERROR;
    }
    return AUTHENTICATION_READ; 
}

static socks5_states authentication_write(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    size_t count;
    uint8_t * bufptr = buffer_read_ptr(&client->write_buffer, &count);
    ssize_t len = send(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len <= 0) {
        return ERROR;
    } else {
        buffer_read_adv(&client->write_buffer, len);
    }
    if (!buffer_can_read(&client->write_buffer)) {
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_READ) || client->auth_info.authenticated == false) {
             return ERROR;        
        }
        return REQUEST_READ;
    }
    return AUTHENTICATION_WRITE; 
}

static void request_read_init(unsigned state, struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    clear_parsing_state(client);
    client->parser = parser_init(parser_no_classes(), request_parser_definition());
}

static socks5_states request_read(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    
    size_t count;
    uint8_t * bufptr = buffer_write_ptr(&client->read_buffer, &count);

    ssize_t len = recv(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len <= 0) {
        return ERROR;
    } else {
        buffer_write_adv(&client->read_buffer, len);
    }
    request_event_type event = request_parser_read(client, &client->read_buffer);
    switch (event) {
        case REQUEST_EVENT_DONE:
            if (client->request_info.cmd != CMD_CONNECT) {
                generate_request_response(&client->write_buffer, REP_COMMAND_NOT_SUPPORTED, ATYP_IPV4, "0.0.0.0", 0);
                if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                    return ERROR;
                }
                return REQUEST_WRITE_ERROR;
            }
            switch (client->request_info.atyp) {
                case ATYP_IPV4: {
                    struct sockaddr_in *addr = (struct sockaddr_in *)&client->destination_addr;
                    client->destination_domain = AF_INET;
                    client->destination_addr_len = sizeof(struct sockaddr_in);
                    
                    memset(addr, 0, sizeof(struct sockaddr_in));
                    addr->sin_family = AF_INET;
                    addr->sin_port = htons(client->request_info.dest_port);
                    
                    if (inet_pton(AF_INET, client->request_info.dest_addr, &addr->sin_addr) <= 0) {
                        generate_request_response(&client->write_buffer, REP_GENERAL_FAILURE,ATYP_IPV4, "0.0.0.0", 0);
                        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                            return ERROR;
                        }
                        return REQUEST_WRITE_ERROR;
                    }
                    
                    
                    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                        return ERROR;
                    }
                    return connect_destination(key);
                }
                
                case ATYP_IPV6: {
                    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&client->destination_addr;
                    client->destination_domain = AF_INET6;
                    client->destination_addr_len = sizeof(struct sockaddr_in6);
                    
                    memset(addr, 0, sizeof(struct sockaddr_in6));
                    addr->sin6_family = AF_INET6;
                    addr->sin6_port = htons(client->request_info.dest_port);
                    
                    if (inet_pton(AF_INET6, client->request_info.dest_addr, &addr->sin6_addr) <= 0) {
                        generate_request_response(&client->write_buffer, REP_GENERAL_FAILURE,ATYP_IPV4, "0.0.0.0", 0);
                        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                            return ERROR;
                        }
                        return REQUEST_WRITE_ERROR;
                    }
                    
                    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                        return ERROR;
                    }
                    
                    return connect_destination(key);
                }
                
                case ATYP_DOMAINNAME: {
                    struct selector_key * k = malloc(sizeof(*key));
                    if (k == NULL) {
                        generate_request_response(&client->write_buffer, REP_GENERAL_FAILURE,ATYP_IPV4, "0.0.0.0", 0);
                        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                            return ERROR;
                        }
                        return REQUEST_WRITE_ERROR;
                    }
                    memcpy(k, key, sizeof(*key));
                    pthread_t thread;
                    if (pthread_create(&thread, NULL, &request_resolv_thread, k) != 0) {
                        free(k);
                        generate_request_response(&client->write_buffer, REP_GENERAL_FAILURE, ATYP_IPV4, "0.0.0.0", 0);
                        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                            return ERROR;
                        }
                        return REQUEST_WRITE_ERROR;
                    }
                    if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
                        return ERROR;
                    }
                    
                    return REQUEST_RESOLV;
                }
                
                default:
                    generate_request_response(&client->write_buffer, REP_ADDRESS_TYPE_NOT_SUPPORTED,ATYP_IPV4, "0.0.0.0", 0);
                    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                        return ERROR;
                    }
                    return REQUEST_WRITE_ERROR;
            }
            
        case REQUEST_EVENT_VERSION_ERROR:
            generate_request_response(&client->write_buffer, REP_GENERAL_FAILURE,ATYP_IPV4, "0.0.0.0", 0);
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                return ERROR;
            }
            return REQUEST_WRITE_ERROR;
            
        case REQUEST_EVENT_CMD_ERROR:
            generate_request_response(&client->write_buffer, REP_COMMAND_NOT_SUPPORTED,ATYP_IPV4, "0.0.0.0", 0);
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                return ERROR;
            }
            return REQUEST_WRITE_ERROR;
            
        case REQUEST_EVENT_ATYP_ERROR:
            generate_request_response(&client->write_buffer, REP_ADDRESS_TYPE_NOT_SUPPORTED,ATYP_IPV4, "0.0.0.0", 0);
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                return ERROR;
            }
            return REQUEST_WRITE_ERROR;
            
        case REQUEST_EVENT_ERROR:
            generate_request_response(&client->write_buffer, REP_GENERAL_FAILURE,ATYP_IPV4, "0.0.0.0", 0);
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                return ERROR;
            }
            return REQUEST_WRITE_ERROR;
            break;
        default:
            break;
    }
    
    return REQUEST_READ;
}

static socks5_states request_resolv(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    
    if (client->resolved_addr == NULL) {
        generate_request_response(&client->write_buffer, REP_HOST_UNREACHABLE,ATYP_IPV4, "0.0.0.0", 0);      
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        return REQUEST_WRITE_ERROR;
    }
    
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    
    return connect_destination(key);
}

static socks5_states request_connect(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    
    int error = 0;
    socklen_t error_size = sizeof(error);
    
    if (getsockopt(client->destination_socket, SOL_SOCKET, SO_ERROR, &error, &error_size) != 0) {
        selector_unregister_fd(key->s, client->destination_socket);
        close(client->destination_socket);
        client->destination_socket = -1;
        return try_next_address(key);
    }
    
    if (error != 0) {
        selector_unregister_fd(key->s, client->destination_socket);
        close(client->destination_socket);
        client->destination_socket = -1;
        return try_next_address(key);
    }


    if (client->resolved_addr != NULL) {
        freeaddrinfo(client->resolved_addr);
        client->resolved_addr = NULL;
        client->resolved_addr_current = NULL;
    }

    if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_NOOP) || 
        SELECTOR_SUCCESS != selector_set_interest(key->s, client->client_socket, OP_WRITE) || 
        generate_request_response(&client->write_buffer, REP_SUCCEEDED, client->request_info.atyp, client->request_info.dest_addr, client->request_info.dest_port) == -1) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

static socks5_states request_write_error(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
     size_t count;
    uint8_t * bufptr = buffer_read_ptr(&client->write_buffer, &count);
    ssize_t len = send(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return ERROR;
    }
    buffer_read_adv(&client->write_buffer, len);


    if (!buffer_can_read(&client->write_buffer)) {
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
            return REQUEST_READ;
        }
        return ERROR;
    }
    return REQUEST_WRITE_ERROR;
}

static socks5_states request_write(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
     size_t count;
    uint8_t * bufptr = buffer_read_ptr(&client->write_buffer, &count);
    ssize_t len = send(client->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return ERROR;
    }
    buffer_read_adv(&client->write_buffer, len);


    if (!buffer_can_read(&client->write_buffer)) {
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ) && SELECTOR_SUCCESS == selector_set_interest(key->s, client->destination_socket, OP_READ)) {
            log_socks5_client_access(client);
            return RELAY_DATA;
        }
        return ERROR;
    }
    return REQUEST_WRITE;
}

static void relay_data_init(unsigned state, struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    clear_parsing_state(client);
    // Inicializar buffers de relay si no están inicializados
    if (client->raw_buffer_client_to_dest == NULL) {
        client->raw_buffer_client_to_dest = malloc(buffer_size);
        buffer_init(&client->client_to_dest_buffer, buffer_size, client->raw_buffer_client_to_dest);
    }
    if (client->raw_buffer_dest_to_client == NULL) {
        client->raw_buffer_dest_to_client = malloc(buffer_size);
        buffer_init(&client->dest_to_client_buffer, buffer_size, client->raw_buffer_dest_to_client);
    }
}   

static socks5_states relay_data_read(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    ssize_t n;
    size_t count;
    uint8_t * write_ptr;
    int fd;
    buffer * target_buffer;
    bool log_transferred_bytes = false;

    // Determinar de dónde viene el evento
    if (key->fd == client->client_socket) {
        // Leer del cliente y guardar en el buffer hacia el destino
        fd = client->client_socket;
        target_buffer = &client->client_to_dest_buffer;
        log_transferred_bytes = false;
    } else if (key->fd == client->destination_socket) {
        // Leer del destino y guardar en el buffer hacia el cliente
        fd = client->destination_socket;
        target_buffer = &client->dest_to_client_buffer;
        log_transferred_bytes = true;
    } else {
        fprintf(stderr, "relay_data_read: fd desconocido (%d)\n", key->fd);
        return ERROR;
    }

    write_ptr = buffer_write_ptr(target_buffer, &count);
    if (count == 0) {
        return RELAY_DATA;
    }
    n = recv(fd, write_ptr, count, MSG_NOSIGNAL);    
    if (n > 0) {
        buffer_write_adv(target_buffer, n);
        if (log_transferred_bytes) {
            add_transfered_bytes(n);
        }
        // Habilitar escritura en el otro socket
        int other_fd = (fd == client->client_socket) ? client->destination_socket : client->client_socket;
        count = 0;
        uint8_t * read_ptr = buffer_read_ptr(target_buffer, &count);
        int written = send(other_fd,read_ptr,count, MSG_NOSIGNAL);

        if(written > 0) { 
            // Se pudo escribir en destino, avanzar el puntero de lectura del buffer
            buffer_read_adv(target_buffer,written);
            if (!log_transferred_bytes) {
                add_transfered_bytes(written);
            }
            // No se pudo escribir todo lo leido del origen al destino, habilitar OP_WRITE en el otro socket
            if(written < count){
                if(selector_set_interest(key->s, other_fd, OP_WRITE) != SELECTOR_SUCCESS) {
                    fprintf(stderr, "relay_data_read: error habilitando OP_WRITE en fd %d\n", other_fd);
                    return ERROR;
                }
            }
            return RELAY_DATA;
        } else if (written == -1) { 
             // El socket no está listo para escribir, esperar próximo evento
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (selector_set_interest(key->s, other_fd, OP_WRITE) != SELECTOR_SUCCESS) {
                    fprintf(stderr, "relay_data_read: error habilitando OP_WRITE en fd %d\n", other_fd);
                    return ERROR;
                }
                return RELAY_DATA;
            } 
            else {
                perror("relay_data_read: recv error");
                return ERROR;
            }
        } else if (written == 0) {
            return DONE;
        }
    } else if (n == 0) {
        return DONE;
    } else {
        // Error en recv
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // El socket no está listo para leer, esperar próximo evento
            return RELAY_DATA;
        } else if (errno == EINTR) {
            // Interrumpido por señal, intentar de nuevo
            return RELAY_DATA;
        } else {
            // Error fatal
            perror("relay_data_read: recv error");
            return ERROR;
        }
    }
    return RELAY_DATA;
}

static socks5_states relay_data_write(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    ssize_t n;
    size_t count;
    uint8_t * read_ptr;
    int fd;
    buffer * source_buffer;
    bool log_transferred_bytes = false;

    // Determinar a dónde va el evento
    if (key->fd == client->destination_socket) {
        // Escribir al destino desde el buffer
        fd = client->destination_socket;
        source_buffer = &client->client_to_dest_buffer;
        log_transferred_bytes = true;
    } else if (key->fd == client->client_socket) {
        // Escribir al cliente desde el buffer
        fd = client->client_socket;
        source_buffer = &client->dest_to_client_buffer;
        log_transferred_bytes = false;
    } else {
        fprintf(stderr, "relay_data_write: fd desconocido (%d)\n", key->fd);
        return ERROR;
    }

    read_ptr = buffer_read_ptr(source_buffer, &count);
    if (count > 0) {
        n = send(fd, read_ptr, count, MSG_NOSIGNAL);
        if (n > 0) {
            buffer_read_adv(source_buffer, n);
            if (log_transferred_bytes) {
                add_transfered_bytes(n);
            }
        } else if (n == 0) {
            return DONE;
        } else {
            // Error en send
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // El socket no está listo para escribir, esperar próximo evento
                return RELAY_DATA;
            } else if (errno == EINTR) {
                // Interrumpido por señal, intentar de nuevo
                return RELAY_DATA;
            } else {
                // Error fatal
                perror("relay_data_write: send error");
                return ERROR;
            }
        }
    }
    // Si el buffer está vacío, deshabilitar interés de escritura
    if (!buffer_can_read(source_buffer)) {
        if (selector_set_interest(key->s, fd, OP_READ) != SELECTOR_SUCCESS) {
            fprintf(stderr, "relay_data_write: error deshabilitando OP_WRITE en fd %d\n", fd);
            return ERROR;
        }
    }
    return RELAY_DATA;
}


static socks5_states try_next_address(struct selector_key * key) {
    client_socks5 * client = (client_socks5 *)key->data;
    

    if (client->resolved_addr != NULL && client->resolved_addr_current != NULL) {
        client->resolved_addr_current = client->resolved_addr_current->ai_next;
        
        if (client->destination_socket != -1) {
            selector_unregister_fd(key->s, client->destination_socket);
            close(client->destination_socket);
            client->destination_socket = -1;
        }

        if (client->resolved_addr_current != NULL) {
            client->connection_attempts++;
            return connect_destination(key);
        }
    }
    if (client->resolved_addr != NULL) {
        freeaddrinfo(client->resolved_addr);
        client->resolved_addr = NULL;
        client->resolved_addr_current = NULL;
    }

    // If we reach here, it means all addresses have been tried and failed and errno was set by the last connect attempt.
    if (generate_request_response(&client->write_buffer, errno_to_socks5_reply(errno), ATYP_IPV4, "0.0.0.0", 0) == -1) {
        return ERROR;
    }
    
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    
    return REQUEST_WRITE_ERROR;
}


static void* request_resolv_thread(void * arg) {
    struct selector_key * key = (struct selector_key *)arg;
    client_socks5 * client = (client_socks5 *)key->data;
    

    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", client->request_info.dest_port);
    
    int status = getaddrinfo(client->request_info.dest_addr, port_str, &hints, &result);
    
    if (status == 0) {
        client->resolved_addr = result;
        client->resolved_addr_current = result;
        client->connection_attempts = 0;  
        
        if (result->ai_family == AF_INET) {
            client->destination_domain = AF_INET;
            client->destination_addr_len = sizeof(struct sockaddr_in);
        } else if (result->ai_family == AF_INET6) {
            client->destination_domain = AF_INET6;
            client->destination_addr_len = sizeof(struct sockaddr_in6);
        }
        memcpy(&client->destination_addr, result->ai_addr, result->ai_addrlen);
        selector_notify_block(key->s, key->fd);
    } else {
        client->resolved_addr = NULL;
        selector_notify_block(key->s, key->fd);
    }
    free(key);
    return NULL;
}

static const struct state_definition states[] = {
    {
        .state = GREETING_READ,
        .on_arrival = greeting_read_init,
        .on_read_ready = greeting_read,
    },
    {
        .state = GREETING_WRITE,
        .on_write_ready = greeting_write,
    },
    {
        .state = AUTHENTICATION_READ,
        .on_arrival = authentication_read_init,
        .on_read_ready = authentication_read,
    },
    {
        .state = AUTHENTICATION_WRITE,
        .on_write_ready = authentication_write,
    },
    {
        .state = REQUEST_READ,
        .on_arrival = request_read_init,
        .on_read_ready = request_read,
    },
    {
        .state = REQUEST_RESOLV,
        .on_block_ready = request_resolv,
    },
    {
        .state = REQUEST_CONNECT,
        .on_write_ready = request_connect,
    },
    {
        .state = REQUEST_WRITE_ERROR,
        .on_write_ready = request_write_error,
    },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = request_write,
    },
    {
        .state = RELAY_DATA,
        .on_arrival = relay_data_init,
        .on_read_ready = relay_data_read,
        .on_write_ready = relay_data_write,
    },
    {
        .state = ERROR,
    },
    {
        .state = DONE,
    },
    {   
        .state = BAD_CREDENTIALS,
    }};

const struct state_definition * get_socks5_states(void) { return states; }

uint32_t socks_get_buffer_size(void) {
    return buffer_size;
}

void socks_set_buffer_size(uint32_t new_buff_size) {
    if (new_buff_size <= 0 || new_buff_size > MAX_SOCKS5_BUFFER_SIZE) {
        return;
    }

    buffer_size = new_buff_size;
}
