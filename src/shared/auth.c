#include "includes/auth.h"

typedef struct UserList {
    const char *username;
    const char *password;
    struct UserList *next;
} UserList;

int users_size = 0;
static UserList * users_list = NULL;
bool auth_enabled = false;

UserList * create_user(const char *username, const char *password);

int add_user(const char * username, const char * password) {
    if(users_size == MAX_USERS){
        return 1;
    }

    if (users_list == NULL){
        users_list = create_user(username, password);
        if (users_list == NULL) {
            return -1;
        }
        return 0;
    }

    UserList * current = users_list;
    while (current != NULL) {
        if (strcmp(current->username, username) == 0) {
            return -1;  
        }

        if (current->next == NULL) {
            current->next = create_user(username, password);
            if (current->next == NULL) {
                return -1;
            }
            return 0;
        }
    
        current = current->next;
    } 
    return 0; // This line should never be reached, but it's here to avoid warnings
}

void remove_user(const char *username) {
    if(users_size == 0){
        return;
    }

    UserList * current = users_list;
    UserList * previous = NULL;

    while (current != NULL) {
        if (strcmp(current->username, username) == 0) {
            if (previous == NULL) {
                users_list = current->next;
            } else {
                previous->next = current->next;
            }
            free((void *) current->username);
            free((void *) current->password);
            free(current);
            users_size--;
            if(users_size == 0){
                auth_enabled = false;
            }
            return;
        }
        previous = current;
        current = current->next;
    }
}

int authenticate_user(const char *username, const char *password) {
    UserList * current = users_list;
    while (current != NULL) {
        if (strcmp(current->username, username) == 0) {
            if (strcmp(current->password, password) == 0) {
                return 0; // Authentication successful
            } 
            return -1; // Incorrect password
        }
        current = current->next;
    }
    return -1; // User not found
}

void destroy_user_list(void) {
    UserList * current = users_list;
    UserList * next;

    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    
    users_list = NULL; // Reset the head of the list
}

uint16_t get_users_separator(char *buffer, size_t buffer_size, const char *separator, size_t separator_size) {
    if (buffer == NULL || buffer_size < separator_size) {
        return 0; // Invalid buffer or insufficient size
    }
    
    buffer[0] = '\0';

    UserList *current = users_list;
    uint16_t current_len = 0;
    while (current != NULL) {
        size_t len = strlen(current->username);
        
        if (current_len + len + separator_size > buffer_size) {
            break; // No hay más espacio
        }
        
        memcpy(&buffer[current_len], current->username, len);
        current_len += len;
        
        memcpy(&buffer[current_len], separator, separator_size);
        current_len += separator_size;
        
        current = current->next;
    }
    return current_len;
}

UserList * create_user(const char *username, const char *password) {
    UserList * new_user = (UserList *) malloc(sizeof(UserList));
    if (new_user == NULL) {
        return NULL; // Memory allocation failed
    }

    new_user->username = strdup(username);
    new_user->password = strdup(password);

    if (new_user->username == NULL || new_user->password == NULL) {
        free((void*)new_user->username);
        free((void*)new_user->password);
        free(new_user);
        return NULL; // Memory allocation failed
    }

    new_user->next = NULL;
    auth_enabled = true;
    users_size++;
    return new_user;
}

bool authentication_enabled(void) {
    return auth_enabled;
}

void print_user_list(void) {
    UserList * current = users_list;
    while (current != NULL) {
        printf("User: %s, Password: %s\n", current->username, current->password);
        current = current->next;
    }
}
