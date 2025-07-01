#include "metrics.h"

typedef struct {
    uint64_t current_connections;
    uint64_t total_transfered_bytes;
    uint64_t historic_connections;
} Metrics;

static Metrics metrics = {
    .current_connections = 0,
    .total_transfered_bytes = 0,
    .historic_connections = 0
};

void add_current_connection(){
    metrics.current_connections++;
    metrics.historic_connections++;
}

void remove_current_connection(){
    if (metrics.current_connections > 0)
        metrics.current_connections--;
} 

void add_transfered_bytes(int bytes){
    metrics.total_transfered_bytes += bytes;
}

int get_current_connections(){
    return metrics.current_connections;
}    

int get_transfered_bytes(){
    return metrics.total_transfered_bytes;
}

int get_historic_connections(){
    return metrics.historic_connections;
}    