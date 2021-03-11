#ifndef PKTCAP_CORE_WRITE_H
#define PKTCAP_CORE_WRITE_H

#include "core_capture.h"
#include <stdbool.h>
#include <stdint.h>

#define PKTCAP_OUTPUT_FILE_LENGTH 100
#define PKTCAP_WRITE_BURST_SIZE 256

struct core_write_stats {
    int core_id;
    char output_file[PKTCAP_CAPTURE_BURST_SIZE];
    uint64_t current_file_packets;
    uint64_t current_file_bytes;
    uint64_t packets;
    uint64_t bytes;
};

struct core_write_config {
    struct rte_ring *ring;
    bool volatile *stop_condition;
    struct core_write_stats *stats;
    char *output_prefix;
    uint32_t snaplen;
};

int write_core(const struct core_write_config *config);

#endif
