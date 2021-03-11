#include <rte_branch_prediction.h>
#include <rte_mbuf_core.h>
#include <rte_ring.h>
#include <signal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_version.h>
#include <rte_log.h>
#include <stdint.h>

#include "core_capture.h"

#define RTE_LOGTYPE_PKTCAP RTE_LOGTYPE_USER1

int capture_core(const struct core_capture_config *config)
{
    struct rte_mbuf *bufs[PKTCAP_CAPTURE_BURST_SIZE];
    uint16_t nb_rx;
    int nb_rx_enqueued;
    int i;

    RTE_LOG(INFO, PKTCAP, "Core %u is capturing packets for port %u\n",
        rte_lcore_id(), config->port);
    
    *(config->stats) = (struct core_capture_stats) {
        .core_id = rte_lcore_id(),
        .packets = 0,
        .missed_packets = 0,
    };

    for (;;) {
        if (unlikely(*(config->stop_condition))) {
            break;
        }
        nb_rx = rte_eth_rx_burst(config->port, config->queue, bufs, PKTCAP_CAPTURE_BURST_SIZE);
        if (likely(nb_rx > 0)) {
            #if RTE_VERSION >= RTE_VERSION_NUM(17, 5, 0, 16)
            nb_rx_enqueued = rte_ring_enqueue_burst(config->ring, (struct rte_mbuf **)bufs, nb_rx, NULL);
            #else
            nb_rx_enqueued = rte_ring_enqueue_burst(config->ring, (struct rte_mbuf **)bufs, nb_rx);
            #endif

            if (nb_rx_enqueued == nb_rx) {
                config->stats->packets += nb_rx;
            } else {
                RTE_LOG(INFO, PKTCAP, "nb_rx: %u nb_rx_enqueued: %u\n", nb_rx, nb_rx_enqueued);
                config->stats->missed_packets += nb_rx;
                for (i = nb_rx_enqueued; i < nb_rx; i++) {
                    rte_pktmbuf_free(bufs[i]);
                }
            }
        }
    }
    RTE_LOG(INFO, PKTCAP, "Closed capture core %d (port %d)\n",
        rte_lcore_id(), config->port);
    return 0;
}
