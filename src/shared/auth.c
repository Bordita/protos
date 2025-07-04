#include "auth.h"

typedef struct UserList {
    const char *username;
    const char *password;
    struct UserList *next;
} UserList;

static UserList * users_list = NULL;
bool auth_enabled = false;

UserList * create_user(const char *username, const char *password);

int add_user(const char * username, const char * password) {
    // If the list is empty, create a new user and set it as the head of the list
    if (users_list == NULL){
        users_list = create_user(username, password);
        if (users_list == NULL) {
            return -1; // Memory allocation failed
        }
        return 0; // User added successfully
    }

    // Check if the user already exists and add it to the end of the list
    UserList * current = users_list;
    while (current != NULL) {
        if (strcmp(current->username, username) == 0) {
            return -1; // User already exists   
        }

        if (current->next == NULL) {
            current->next = create_user(username, password);
            if (current->next == NULL) {
                return -1; // Memory allocation failed
            }
            return 0; // User added successfully
        }
    
        current = current->next;
    } 
    return 0; // This line should never be reached, but it's here to avoid warnings
}

void remove_user(const char *username) {
    UserList * current = users_list;
    UserList * previous = NULL;

    while (current != NULL) {
        if (strcmp(current->username, username) == 0) {
            // User found, remove it from the list
            if (previous == NULL) {
                // Removing the head of the list
                users_list = current->next;
            } else {
                // Removing a user from the middle or end of the list
                previous->next = current->next;
            }
            free(current);
            return; // User removed successfully
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


UserList * create_user(const char *username, const char *password) {
    UserList * new_user = (UserList *) malloc(sizeof(UserList));
    if (new_user == NULL) {
        return NULL; // Memory allocation failed
    }

    new_user->username = username;
    new_user->password = password;
    new_user->next = NULL;
    return new_user;
}

bool authentication_enabled(void) {
    return auth_enabled;
}
