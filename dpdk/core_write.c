#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_ring.h>
#include <rte_version.h>
#include <rte_mbuf.h>

#include "core_write.h"
#include "pcap.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define RTE_LOGTYPE_PKTCAP RTE_LOGTYPE_USER1

static void format_from_template(char *filename, const char *template,
                                 const char core_id) {
  char str_buf[PKTCAP_OUTPUT_FILE_LENGTH];
  snprintf(str_buf, PKTCAP_OUTPUT_FILE_LENGTH, "%s-%u.pcap", template, core_id);
}

static FILE *open_pcap(char *output_file) {
  FILE *file;
  file = fopen(output_file, "w");
  if (unlikely(!file)) {
    RTE_LOG(ERR, PKTCAP, "Core %d could not open %s in write mode: %d (%s)\n",
            rte_lcore_id(), output_file, errno, strerror(errno));
  }
  return file;
}

static int write_pcap(FILE *file, void *buf, size_t len) {
  size_t retval;
  retval = fwrite(buf, len, 1, file);
    if (unlikely(retval != 1)) {
    RTE_LOG(ERR, PKTCAP, "Could not write into file: %d (%s)\n", errno,
            strerror(errno));
    return -1;
    }
    return retval;
}

static int close_pcap(FILE *file) {
  int retval;
  retval = fclose(file);
  if (unlikely(retval)) {
    RTE_LOG(ERR, PKTCAP, "Could not close file: %d (%s)\n", errno,
            strerror(errno));
  }
  return retval;
}

int write_core(const struct core_write_config *config) {
  FILE *output;
  uint32_t packet_length, wire_packet_length;
  struct pcap_header header;
  struct pcap_packet_header packet_header;
  int retval = 0;
  int written;
  int file_size = 0;
  struct rte_mbuf *dequeued[PKTCAP_WRITE_BURST_SIZE];
  struct rte_mbuf *bufptr;
  struct timeval tv;

  *(config->stats) = (struct core_write_stats){
      .core_id = rte_lcore_id(),
      .current_file_packets = 0,
      .current_file_bytes = 0,
      .packets = 0,
      .bytes = 0,
  };

  snprintf(config->stats->output_file, PKTCAP_OUTPUT_FILE_LENGTH, "%s-%u.pcap",
           config->output_prefix, rte_lcore_id());

  pcap_header_init(&header, config->snaplen);
  output = open_pcap(config->stats->output_file);
  if (unlikely(!output)) {
    retval = -1;
    goto cleanup;
  }

  written = write_pcap(output, &header, sizeof(struct pcap_header));
  if (unlikely(written < 0)) {
    retval = -1;
    goto cleanup;
  }
  file_size = written;

  RTE_LOG(INFO, PKTCAP, "Core %d is writing to file %s\n", rte_lcore_id(),
          config->stats->output_file);

  for (;;) {
    if (unlikely(*(config->stop_condition) && rte_ring_empty(config->ring))) {
      break;
    }

    int to_write;
#if RTE_VERSION >= RTE_VERSION_NUM(17, 5, 0, 16)
    to_write = rte_ring_dequeue_burst(config->ring, (struct rte_mbuf **)dequeued,
                                      PKTCAP_WRITE_BURST_SIZE, NULL);
#else
    to_write =
        rte_ring_dequeue_burst(config->ring, (struct rte_mbuf **)dequeued, PKTCAP_WRITE_BURST_SIZE);
#endif
    config->stats->packets += to_write;
    int i;
    for (i = 0; i < to_write; i++) {
        bufptr = dequeued[i];
        wire_packet_length = rte_pktmbuf_pkt_len(bufptr);
        packet_length = MIN(config->snaplen, wire_packet_length);
        gettimeofday(&tv, 0);

        // Write Packet Header
        packet_header.timestamp = tv.tv_sec;
        packet_header.microseconds = tv.tv_usec;
        packet_header.packet_length = packet_length;
        packet_header.packet_length_wire = wire_packet_length;
        written = write_pcap(output, &packet_header, sizeof(struct pcap_packet_header));

        if (unlikely(written) < 0) {
            retval = -1;
            goto cleanup;
        }
        file_size += written;

        // Write Packet Content
        int remaining_bytes = packet_length;
        while (bufptr != NULL && remaining_bytes > 0) {
            int bytes_to_write = MIN(rte_pktmbuf_data_len(bufptr), remaining_bytes);
            written = write_pcap(output, rte_pktmbuf_mtod(bufptr, void *), bytes_to_write);
            if (unlikely(written < 0)) {
                retval = -1;
                goto cleanup;
            }
            bufptr = bufptr->next;
            remaining_bytes -= bytes_to_write;
            file_size += written;
        }

        // Free buffer
        rte_pktmbuf_free(dequeued[i]);

        // Update stats
        config->stats->bytes += packet_length;
        config->stats->current_file_packets++;
        config->stats->current_file_bytes += packet_length;
    }
  }

  cleanup:
  close_pcap(output);
  RTE_LOG(INFO, PKTCAP, "Closed writing core %d\n", rte_lcore_id());
  return retval;
}
