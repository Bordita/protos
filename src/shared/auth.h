#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdio.h>

int add_user(const char *username, const char *password);
void remove_user(const char *username);
int authenticate_user(const char *username, const char *password);

void destroy_user_list();

#endif