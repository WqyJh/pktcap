#ifndef PKTCAP_CORE_CAPTURE_H
#define PKTCAP_CORE_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>

#define PKTCAP_CAPTURE_BURST_SIZE 256

struct core_capture_stats {
    int core_id;
    uint64_t packets; // packets sucessfully enqueued
    uint64_t missed_packets; // packets core could not enqueue
};

struct core_capture_config {
    struct rte_ring *ring;
    bool volatile *stop_condition;
    struct core_capture_stats *stats;
    uint8_t port;
    uint8_t queue;
};

int capture_core(const struct core_capture_config *config);

#endif
