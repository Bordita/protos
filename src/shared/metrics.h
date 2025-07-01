#ifndef __METRICS_H__
#define __METRICS_H__

#include <stdint.h>

// TODO: check if can use <stdatomic.h> for atomic operations

void add_current_connection();    // Add a new connection to the historics and to current connections
void remove_current_connection(); // Remove a connection from the current connections

void add_transfered_bytes(int bytes); // Add bytes to the total transfer bytes

int get_current_connections();    // Get the number of current connections
int get_transfered_bytes();            // Get the total transfer bytes
int get_historic_connections();    // Get the total number of connections

#endif