/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <argp.h>

#include <rte_common.h>
#include <rte_launch.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include <rte_version.h>

#include "core_capture.h"
#include "core_write.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define MAX_LCORES 1000

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32

#define RTE_LOGTYPE_PKTCAP RTE_LOGTYPE_USER1
#define PKTCAP_OUTPUT_PREFIX "output"


const char *argp_program_version = "pktcap 1.0";
const char *argp_program_bug_address = "qiyingwangwqy@gmail.com";
static char doc[] = "A DPDK-based packet capture tool";
static char args_doc[] = "";
static struct argp_option options[] = {
	{"output", 'o', "FILE", 0, "Output file prefix (dont't add the extension).", 0},
	{"snaplen", 's', "LENGTH", 0, "Snap the capture to snaplen bytes (default: 65535).", 0},
	{"portmask", 'p', "PORTMASK", 0, "Ethernet ports mask (default: 0x1).", 0},
	{"per_port_c_cores", 'c', "NB_CORES_PER_PORT", 0, "Number of cores per port used for capture (default: 1)", 0 },
	{"num_w_cores", 'w', "NB_CORES", 0, "Total number of cores used for writing (default: 1).", 0},
	{ 0 }
};

struct arguments {
	char *args[2];
	char output_file_prefix[PKTCAP_OUTPUT_FILE_LENGTH];
	uint32_t snaplen;
	uint64_t portmask;
	uint32_t per_port_c_cores;
	uint32_t num_w_cores;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;
	char *end;
	errno = 0;
	end = NULL;
	switch (key) {
		case 'o':
			strncpy(arguments->output_file_prefix, arg, PKTCAP_OUTPUT_FILE_LENGTH);
			break;
		case 's':
			arguments->snaplen = strtoul(arg, &end, 10);
			break;
		case 'p':
			arguments->portmask = strtoul(arg, &end, 16);
			if (arguments->portmask == 0) {
				RTE_LOG(ERR, PKTCAP, "Invalid portmask '%s', no port used\n", arg);
				return -EINVAL;
			}
			break;
		case 'c':
			arguments->per_port_c_cores = strtoul(arg, &end, 10);
			break;
		case 'w':
			arguments->num_w_cores = strtoul(arg, &end, 10);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	if (errno || (end != NULL && *end != '\0')) {
		RTE_LOG(ERR, PKTCAP, "Invalid value '%s'\n", arg);
		return -EINVAL;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0};
struct arguments arguments;



// -------------------------------------------------------------

static struct rte_ring *write_ring;

static uint32_t portlist[64];
static uint32_t nb_ports;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_NONE,
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	}
};

static int port_init(
	uint8_t port,
	const uint16_t rx_rings,
	unsigned int num_rxdesc,
	struct rte_mempool *mbuf_pool
)
{
	struct rte_eth_conf port_conf = port_conf_default;
	struct rte_eth_dev_info dev_info;
	int retval;
	uint16_t q;
	uint16_t dev_count;

	#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 3, 16)
	dev_count = rte_eth_dev_count_avail() - 1;
	#else
	dev_count = rte_eth_dev_count() - 1;
	#endif

	if (rte_eth_dev_is_valid_port(port) == 0) {
		RTE_LOG(ERR, PKTCAP, "Port identifier %d out of range (0 to %d) or not attached.\n",
			port, dev_count);
		return -EINVAL;
	}
	rte_eth_dev_info_get(port, &dev_info);
	if (rx_rings > dev_info.max_rx_queues) {
		RTE_LOG(ERR, PKTCAP, "Port %d can only handle up to %d queues (%d requested).\n",
			port, dev_info.max_rx_queues, rx_rings);
		return -EINVAL;
	}

	if (num_rxdesc > dev_info.rx_desc_lim.nb_max ||
		num_rxdesc < dev_info.rx_desc_lim.nb_min ||
		num_rxdesc % dev_info.rx_desc_lim.nb_align != 0) {
		RTE_LOG(ERR, PKTCAP, "Port %d cannot be configured with %d RX descriptors per queue (min:%d, max:%d, align:%d)\n",
			port, num_rxdesc, dev_info.rx_desc_lim.nb_min, dev_info.rx_desc_lim.nb_max, dev_info.rx_desc_lim.nb_align);
		return -EINVAL;
	}

	// Configure multiqueue (Activate Receive Side Scaling on UDP/TCP fields)
	if (rx_rings > 1) {
		port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
		port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
		port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_PROTO_MASK;
	}

	retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
	if (retval) {
		RTE_LOG(ERR, PKTCAP, "rte_eth_dev_configure(...): %s\n", rte_strerror(-retval));
		return retval;
	}

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, num_rxdesc, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval) {
			RTE_LOG(ERR, PKTCAP, "rte_eth_rx_queue_setup(...): %s\n",
				rte_strerror(-retval));
			return retval;
		}
	}

	if (dev_info.max_rx_queues > 1) {
		for (q = 0; q < rx_rings; q++) {
			retval = rte_eth_dev_set_rx_queue_stats_mapping(port, q, q);
			if (retval) {
				RTE_LOG(WARNING, PKTCAP, "rte_eth_dev_set_rx_queue_stats_mapping(...): %s\n", rte_strerror(-retval));
				RTE_LOG(WARNING, PKTCAP, "The queues statistics mapping failed. The displayed queue statistics are thus unreliable.\n");
			}
		}
	}

	// Enable RX in promiscuous mode
	rte_eth_promiscuous_enable(port);

	// Display the port MAC address
	struct rte_ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	RTE_LOG(INFO, PKTCAP, "Port %u: MAC=%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ", RXdesc/queue=%d\n", port,
		addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
		addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5],
		num_rxdesc);
	return 0;
}

/*
* Signal handler
*/
static volatile _Bool should_stop = false;
static void signal_handler(int sig) {
	RTE_LOG(NOTICE, PKTCAP, "Caught signal %s on core %u%s\n",
		strsignal(sig), rte_lcore_id(),
		rte_get_master_lcore() == rte_lcore_id() ? " (MASTER CORE)": "");
	should_stop = true;
}

int main(int argc, char *argv[])
{
	signal(SIGINT, signal_handler);
	struct core_capture_config *capture_config_list;
	struct core_write_config *write_config_list;
	struct core_write_stats *write_stats_list;
	struct core_capture_stats *capture_stats_list;
	unsigned int lcoreid_list[MAX_LCORES];
	uint16_t dev_count;
	unsigned int nb_cores;
	unsigned int nb_lcores;
	unsigned int required_cores;
	struct rte_mempool *mbuf_pool;


	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	// set arguments defaults
	arguments = (struct arguments) {
		.snaplen = 65536,
		.portmask = 0x1,
		.per_port_c_cores = 1,
      	.num_w_cores = 1,
	};
	strncpy(arguments.output_file_prefix, PKTCAP_OUTPUT_PREFIX, PKTCAP_OUTPUT_FILE_LENGTH);
	// parse arguments
	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	#if RTE_VERSION >= RTE_VERSION_NUM(17,5,0,16)
	rte_log_set_level(RTE_LOG_DEBUG, RTE_LOG_DEBUG);
	#else
	rte_set_log_type(RTE_LOGTYPE_PKTCAP, 1);
	rte_set_log_level(RTE_LOG_DEBUG);
	#endif

	/* Check if at least one port is available */
	#if RTE_VERSION >= RTE_VERSION_NUM(18,11,3,16)
	dev_count = rte_eth_dev_count_avail();
	#else
	dev_count = rte_eth_dev_count();
	#endif

	if (dev_count == 0)
		rte_exit(EXIT_FAILURE, "Error: No port available.\n");

	// Create the port list
	nb_ports = 0;
	for (int i = 0; i < 64; i++) {
		if (!((uint64_t)(1ULL << i)) & arguments.portmask)
			continue;
		if (i < dev_count)
			portlist[nb_ports++] = i;
		else
			RTE_LOG(WARNING, PKTCAP, "Warning: port %d is in portmask, but not enough ports are available. Ignoring...\n", i);
	}
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "Error: Found no usable port. Check portmask option.\n");

	RTE_LOG(INFO, PKTCAP, "Using %u ports to listen on\n", nb_ports);

	// Checks core number
	required_cores = 1 + arguments.per_port_c_cores*nb_cores + arguments.num_w_cores;
	if (rte_lcore_count() < required_cores) {
		rte_exit(EXIT_FAILURE, "Assign at least %d cores to pktcap.\n", required_cores);
	}
	RTE_LOG(INFO, PKTCAP, "Using %u cores out of %d allocated\n", required_cores, rte_lcore_count());
	
	// Create mbuf pool
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	// Create write ring
	write_ring = rte_ring_create("Ring for writing", rte_align32pow2(NUM_MBUFS), rte_socket_id(), 0);

	// Core index
	int core_index = rte_get_next_lcore(-1, 1, 0);

	// Init stats/config list
	write_stats_list = malloc(sizeof(struct core_write_stats) * arguments.num_w_cores);
	capture_stats_list = malloc(sizeof(struct core_capture_stats) * arguments.per_port_c_cores * nb_ports);
	write_config_list = malloc(sizeof(struct core_write_config) * arguments.num_w_cores);
	capture_config_list = malloc(sizeof(struct core_capture_config) * arguments.per_port_c_cores * nb_ports);

	nb_lcores = 0;
	// Writing cores
	for (int i = 0; i < arguments.num_w_cores; i++) {
		// Create write config
                struct core_write_config *config = &(write_config_list[i]);
                config->ring = write_ring;
		config->stop_condition = &should_stop;
                config->stats = &(write_stats_list[i]);
                config->output_prefix = arguments.output_file_prefix;
		config->snaplen = arguments.snaplen;

		// Launch writing core
		if (rte_eal_remote_launch((int(*)(void *))write_core, config, core_index) < 0)
			rte_exit(EXIT_FAILURE, "Could not launch writing process on lcore %d.\n", core_index);
		lcoreid_list[nb_lcores++] = core_index;
		core_index = rte_get_next_lcore(core_index, SKIP_MASTER, 0);
	}

	// For each port
	for (int i = 0; i < nb_ports; i++) {
		int port_id = portlist[i];
		int retval = port_init(port_id, arguments.per_port_c_cores, 512, mbuf_pool);
		if (retval) {
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n", port_id);
		}

		// Capture cores for each port
		for (int j = 0; j < arguments.per_port_c_cores; j++) {
                  struct core_capture_config *config =
                      &(capture_config_list[i]);
                  config->ring = write_ring;
                  config->stop_condition = &should_stop;
                  config->stats =
                      &(capture_stats_list[j + i * arguments.per_port_c_cores]);
                  config->port = port_id;
                  config->queue = j;

                  // Launch capture core
                  if (rte_eal_remote_launch((int (*)(void *))capture_core,
                                            config, core_index) < 0)
                    rte_exit(EXIT_FAILURE,
                             "Could not launch capture process on lcore %d.\n",
                             core_index);
                  lcoreid_list[nb_lcores++] = core_index;
                  core_index = rte_get_next_lcore(core_index, SKIP_MASTER, 0);
		}

		retval = rte_eth_dev_start(port_id);
		if (retval) {
			rte_exit(EXIT_FAILURE, "Cannot start port %"PRIu8"\n", port_id);
		}
	}

	// Wait for all cores to complete and exit
	RTE_LOG(NOTICE, PKTCAP, "Waiting for all cores to exit\n");
	for (int i = 0; i < nb_lcores; i++) {
		int result = rte_eal_wait_lcore(lcoreid_list[i]);
		if (result < 0) {
			RTE_LOG(ERR, PKTCAP, "Core %d did not stop correctly.\n", lcoreid_list[i]);
		}
	}

	// Finalize
        free(capture_config_list);
        free(write_config_list);
        free(capture_stats_list);
        free(write_stats_list);
        return 0;
}

