/*
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2017 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without 
 *   modification, are permitted provided that the following conditions 
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright 
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright 
 *       notice, this list of conditions and the following disclaimer in 
 *       the documentation and/or other materials provided with the 
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its 
 *       contributors may be used to endorse or promote products derived 
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 *  version: RWPA_VNF.L.18.02.0-42
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_gre.h>
#include <rte_arp.h>
#include <rte_hash.h>

#include "../rwpa_dp/counter.h"
#include "../rwpa_dp/seq_num.h"
#include "../rwpa_dp/parser.h"
#include "../rwpa_dp/meta.h"
#include "../rwpa_dp/gre.h"
#include "../rwpa_dp/r-wpa_global_vars.h"

static volatile bool force_quit;

enum mode {
    MODE_LOOPBACK = 0,
    MODE_GRE_AND_FWD,
    MODE_DELAY
};

/* MAC updating enabled by default */
static int mac_updating = 1;

/* Loopback mode by default */
static enum mode mode = MODE_LOOPBACK;

#define RTE_LOGTYPE_RWPA_TEST_SIM RTE_LOGTYPE_USER1

#define NB_MBUF   8192

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr rwpa_test_sim_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t rwpa_test_sim_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t rwpa_test_sim_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int rwpa_test_sim_rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
    unsigned n_rx_port;
    unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

/* Table for storing IP and MAC addresses to handle complex delay simulation. */
struct arp_table {
    struct ether_addr dst_mac;
};

#define ARP_TABLE_SIZE 10
struct arp_table arp_table[ARP_TABLE_SIZE];
static struct rte_hash *arp_store = NULL;

void arp_store_init(void);
static int do_address_logic(struct rte_mbuf *m, unsigned portid);

static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 0, /**< IP checksum offload disabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 1, /**< CRC stripped by hardware */
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

struct rte_mempool * rwpa_test_sim_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct rwpa_test_sim_port_statistics {
    uint64_t tx;
    uint64_t rx;
    uint64_t dropped;
} __rte_cache_aligned;
struct rwpa_test_sim_port_statistics port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 10; /* default period is 10 seconds */
#define MAX_DELAY_PERIOD 100000000 /* max delay of 1 second */
static uint64_t delay_cycles_a = 1000; /* default delay-a is 1mS */
static uint64_t delay_cycles_b = 1000; /* default delay-b is 1mS */
#define DELAY_A 0
#define DELAY_B 1
#define DELAY_NONE 2
/* IP address to implement delay b on*/
uint32_t delay_b_ip_addr = 0;
char delay_b_ip_str[256];
/* IP address to implement no delay on*/
uint32_t delay_none_ip_addr = 0;
char delay_none_ip_str[256];
#define DELAY_BUFFER_SIZE 32

/* IP whitelist */
#define IP_WL_LEN 3
static uint32_t ip_wl[IP_WL_LEN];

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
    uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
    unsigned portid;

    total_packets_dropped = 0;
    total_packets_tx = 0;
    total_packets_rx = 0;

    const char clr[] = { 27, '[', '2', 'J', '\0' };
    const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

        /* Clear screen and move to top left */
    printf("%s%s", clr, topLeft);

    printf("\nPort statistics ====================================");

    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
        /* skip disabled ports */
        if ((rwpa_test_sim_enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("\nStatistics for port %u ------------------------------"
               "\nPackets sent: %24"PRIu64
               "\nPackets received: %20"PRIu64
               "\nPackets dropped: %21"PRIu64,
               portid,
               port_statistics[portid].tx,
               port_statistics[portid].rx,
               port_statistics[portid].dropped);

        total_packets_dropped += port_statistics[portid].dropped;
        total_packets_tx += port_statistics[portid].tx;
        total_packets_rx += port_statistics[portid].rx;
    }
    printf("\nAggregate statistics ==============================="
           "\nTotal packets sent: %18"PRIu64
           "\nTotal packets received: %14"PRIu64
           "\nTotal packets dropped: %15"PRIu64,
           total_packets_tx,
           total_packets_rx,
           total_packets_dropped);
    printf("\n====================================================\n");
}

/* initialize IP whitelist */
static void
init_ip_wl(void)
{
    ip_wl[0] = IPv4(1,1,1,1);
    ip_wl[1] = IPv4(2,2,2,2);
    ip_wl[2] = IPv4(192,168,1,103);
}

/* check a packets's src ip is on the whitelist */
static int
is_on_ip_wl(struct rte_mbuf *m)
{
    struct ipv4_hdr *ip =
        rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
                                sizeof(struct ether_hdr));
    uint32_t s_addr = rte_be_to_cpu_32(ip->src_addr);
    int found = 0;

    for (unsigned i = 0; i< IP_WL_LEN; i++){
        if (ip_wl[i] == s_addr) {
            found = 1;
            break;
        }
    }

    return found;
}

/* swap the source and destination IP addresses in an IPv4 header */
static void
swap_ips(struct ipv4_hdr *ip)
{
    uint32_t src = ip->src_addr;
    ip->src_addr = ip->dst_addr;
    ip->dst_addr = src;
}


/* swap the source and destination MAC addresses in an Ethernet header */
static void
swap_macs(struct ether_hdr *eth_hdr)
{
    struct ether_addr src = eth_hdr->s_addr;
    eth_hdr->s_addr = eth_hdr->d_addr;
    eth_hdr->d_addr = src;
}

/* swap the addresses within an Ethernet packet */
static void
swap_pkt(struct rte_mbuf *m)
{
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)&eth_hdr[1];
    struct gre_hdr *gre_hdr = (struct gre_hdr *)&ipv4_hdr[1];
    uint16_t gre_hdr_sz = sizeof(struct gre_hdr);

    /* swap outer MAC addresses */
    swap_macs(eth_hdr);

    /* swap outer IP addresses */
    swap_ips(ipv4_hdr);

    /* get gre header size */
    if (gre_hdr->c) gre_hdr_sz += 4; /* checksum */
    if (gre_hdr->k) gre_hdr_sz += 4; /* key */
    if (gre_hdr->s) gre_hdr_sz += 4; /* sequence number */

    /* swap inner MAC addresses */
    eth_hdr = (struct ether_hdr *)(((uint8_t *)gre_hdr) + gre_hdr_sz);
    swap_macs(eth_hdr);

    /* swap inner IP addresses */
    ipv4_hdr = (struct ipv4_hdr *)&eth_hdr[1];
    swap_ips(ipv4_hdr);
}

static void
rwpa_test_sim_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
{
    struct ether_hdr *eth;
    void *tmp;

    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

    /* 02:00:00:00:00:xx */
    tmp = &eth->d_addr.addr_bytes[0];
    *((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

    /* src addr */
    ether_addr_copy(&rwpa_test_sim_ports_eth_addr[dest_portid], &eth->s_addr);
}

void arp_store_init(void)
{
    char name[RTE_HASH_NAMESIZE] = "arp_store";

    struct rte_hash_parameters arp_hash_params = {
            .name = name,
            .entries = ARP_TABLE_SIZE,
            .key_len = sizeof(uint32_t)
    };

    arp_store = rte_hash_create(&arp_hash_params);
    if (arp_store == NULL)
        rte_panic("Error creating arp store, exiting\n");

    memset(&arp_table, 0x0, sizeof(arp_table));
}

static int
do_address_logic(struct rte_mbuf *m, unsigned portid) {
    struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    int index, ret = DELAY_A;
    unsigned dst_port = rwpa_test_sim_dst_ports[portid];
    struct ipv4_hdr *ip_hdr;

    /* Check IP src/dst to determine if no delay should be implemented. */
    if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
        ip_hdr = (struct ipv4_hdr *)&eth[1];
        if (ip_hdr->dst_addr == delay_none_ip_addr || ip_hdr->src_addr == delay_none_ip_addr)
            ret = DELAY_NONE;
    }

    /* Check IP src/dst to determine which delay to implement. */
    if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
        ip_hdr = (struct ipv4_hdr *)&eth[1];
        if (ip_hdr->dst_addr == delay_b_ip_addr || ip_hdr->src_addr == delay_b_ip_addr)
            ret = DELAY_B;
    }

    /* Fill in dst mac addr if saved previously. */
    if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
        index = rte_hash_lookup(arp_store, &ip_hdr->dst_addr);
        if (index >= 0)
            ether_addr_copy(&arp_table[index].dst_mac, &eth->d_addr);
    }

    /* Learning of addresses during arp messages. */
    if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {
        struct ether_addr tmp = {.addr_bytes = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}};
        struct arp_hdr *arp_hdr = (struct arp_hdr *)&eth[1];
        uint32_t ip_addr;

        if (!is_same_ether_addr(&eth->d_addr, &tmp)) {
            /* Add src ip and mac to arp tables. */
            ip_addr = arp_hdr->arp_data.arp_sip;
            index = rte_hash_add_key(arp_store, &ip_addr);
            if (index >= 0)
                ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_table[index].dst_mac);

            /* Check for dest ip in arp tables, if present set dest mac for arp and eth hdrs. */
            ip_addr = arp_hdr->arp_data.arp_tip;
            index = rte_hash_lookup(arp_store, &ip_addr);
            if (index >= 0) {
                ether_addr_copy(&arp_table[index].dst_mac, &arp_hdr->arp_data.arp_tha);
                ether_addr_copy(&arp_table[index].dst_mac, &eth->d_addr);
                /* Set arp sha to mac address of tx port. */
                rte_eth_macaddr_get(dst_port, &arp_hdr->arp_data.arp_sha);
            }
        } else {
            /* Add src ip and mac to arp tables. */
            ip_addr = arp_hdr->arp_data.arp_sip;
            index = rte_hash_add_key(arp_store, &ip_addr);
            if (index >= 0)
                ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_table[index].dst_mac);
            /* Set arp sha to mac address of tx port. */
            rte_eth_macaddr_get(dst_port, &arp_hdr->arp_data.arp_sha);
        }
    }
    /* Write in src mac addr as that of Port that will Tx packet. */
    rte_eth_macaddr_get(dst_port, &eth->s_addr);
    return ret;
}


static void
rwpa_test_sim_simple_forward(struct rte_mbuf *m, unsigned portid)
{
    unsigned dst_port;
    int sent;
    struct rte_eth_dev_tx_buffer *buffer;

    dst_port = rwpa_test_sim_dst_ports[portid];

    if (mac_updating)
        rwpa_test_sim_mac_updating(m, dst_port);

    buffer = tx_buffer[dst_port];
    sent = rte_eth_tx_buffer(dst_port, 0, buffer, m);
    if (sent)
        port_statistics[dst_port].tx += sent;
}

static void
send_to_iperf(struct rte_mbuf *m, uint8_t portid) {
    if (gre_decap(m, NULL) == RWPA_STS_OK)
        rwpa_test_sim_simple_forward(m, portid);
    else
        rte_pktmbuf_free(m);
}

/* MAC and IP addresses for gre encapsulation. */
static void
send_to_vnf(struct rte_mbuf *m, uint8_t portid) {
    struct ether_addr tun_src_mac = { .addr_bytes={0x01, 0x03, 0x04, 0x06, 0x08, 0x90}};
    struct ether_addr tun_dest_mac = { .addr_bytes={0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
    if (gre_encap(m,
                  IPv4(192,168,1,145), &tun_src_mac,
                  IPv4(192,168,1,103), &tun_dest_mac,
                  0, 0) == RWPA_STS_OK)
        rwpa_test_sim_simple_forward(m, portid);
    else
        rte_pktmbuf_free(m);
}

/*
 * This is used in gre-and-fwd mode.
 * MAC address inline used to determine direction of traffic.
 */
static uint8_t
pkt_for_iperf(struct rte_mbuf *m) {
    struct ether_hdr *hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    uint64_t s_addr = *(uint64_t *)&hdr->s_addr;
    s_addr = s_addr & 0xFFFFFFFFFFFF;
    /* src mac != iperf interface mac addr. - note endianess 00:00:00:00:00:04 */
    if (s_addr != 0x040000000000) {
        /* for iperf. */
        return 1;
    } else {
        /* for vnf. */
        return 0;
    }
}

/* main processing loop */
static void
rwpa_test_sim_main_loop(void)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m;
    int sent;
    unsigned lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    unsigned i, j, portid, nb_rx;
    struct lcore_queue_conf *qconf;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
            BURST_TX_DRAIN_US;
    struct rte_eth_dev_tx_buffer *buffer;
    uint64_t time_to_transmit;
    struct rte_mbuf *delayed_pkts[DELAY_BUFFER_SIZE] = {NULL};
    uint8_t pkt_present[DELAY_BUFFER_SIZE] = {0};
    uint64_t pkt_tx_time[DELAY_BUFFER_SIZE] = {0};
    int delay = 0;

    prev_tsc = 0;
    timer_tsc = 0;

    lcore_id = rte_lcore_id();
    qconf = &lcore_queue_conf[lcore_id];

    if (qconf->n_rx_port == 0) {
        RTE_LOG(INFO, RWPA_TEST_SIM, "lcore %u has nothing to do\n", lcore_id);
        return;
    }

    RTE_LOG(INFO, RWPA_TEST_SIM, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_rx_port; i++) {
        portid = qconf->rx_port_list[i];
        RTE_LOG(INFO, RWPA_TEST_SIM, " -- lcoreid=%u portid=%u\n", lcore_id,
            portid);
    }

    while (!force_quit) {

        cur_tsc = rte_rdtsc();

        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {

            for (i = 0; i < qconf->n_rx_port; i++) {
                portid = rwpa_test_sim_dst_ports[qconf->rx_port_list[i]];
                buffer = tx_buffer[portid];

                sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
                if (sent)
                    port_statistics[portid].tx += sent;

            }

            /* if timer is enabled */
            if (timer_period > 0) {

                /* advance the timer */
                timer_tsc += diff_tsc;

                /* if timer has reached its timeout */
                if (unlikely(timer_tsc >= timer_period)) {

                    /* do this only on master core */
                    if (lcore_id == rte_get_master_lcore()) {
                        print_stats();
                        /* reset the timer */
                        timer_tsc = 0;
                    }
                }
            }

            prev_tsc = cur_tsc;
        }

        /*
         * Read packet from RX queues
         */
        for (i = 0; i < qconf->n_rx_port; i++) {

            portid = qconf->rx_port_list[i];
            nb_rx = rte_eth_rx_burst((uint8_t) portid, 0,
                         pkts_burst, MAX_PKT_BURST);

            port_statistics[portid].rx += nb_rx;

            for (j = 0; j < nb_rx; j++) {
                m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                if (mode == MODE_LOOPBACK) {
                    if (is_on_ip_wl(m)) {
                        swap_pkt(m);
                        rwpa_test_sim_simple_forward(m, portid);
                    } else {
                        rte_pktmbuf_free(m);
                    }
                } else if (mode == MODE_GRE_AND_FWD) {
                    if (pkt_for_iperf(m))
                        send_to_iperf(m, portid);
                    else
                        send_to_vnf(m, portid);
                } else if (mode == MODE_DELAY) {
		    delay = do_address_logic(m, portid);
		    if (delay == DELAY_NONE)
                        /* Don't delay. */
			time_to_transmit = cur_tsc;
                    else if (delay == DELAY_A)
                        /* Determine delay required in clock ticks. */
                        time_to_transmit = cur_tsc + delay_cycles_a;
                    else
                        /* Determine delay required in clock ticks. */
                        time_to_transmit = cur_tsc + delay_cycles_b;

                    if (rte_rdtsc() > time_to_transmit)
                        /* If delay complete - forward pkt. */
                        rwpa_test_sim_simple_forward(m, portid);
                    else {
                        int k = 0;
                        while (k < DELAY_BUFFER_SIZE && pkt_present[k] == 1) {
                            k++;
                        }
                        if (k < DELAY_BUFFER_SIZE && pkt_present[k] == 0) {
                            /* Space in delay buffer so store pkt and tx time. */
                            delayed_pkts[k] = rte_pktmbuf_alloc(rwpa_test_sim_pktmbuf_pool);
                            *delayed_pkts[k] = *m;
                            rte_memcpy(rte_pktmbuf_mtod(m, uint8_t *), rte_pktmbuf_mtod(delayed_pkts[k], uint8_t *), m->data_len);
                            rte_pktmbuf_free(m);
                            pkt_tx_time[k] = time_to_transmit;
                            pkt_present[k] = 1;
                        } else {
                            /* No space in delay buffer so drop pkt. */
                            rte_pktmbuf_free(m);
                        }
                    }
                }
            }
            if (mode == MODE_DELAY) {
                for (j = 0; j < DELAY_BUFFER_SIZE; j++) {
                    if (pkt_present[j] == 1 && rte_rdtsc() > pkt_tx_time[j]) {
                        /* Delay is complete - Send pkt. */
                        pkt_present[j] = 0;
                        rwpa_test_sim_simple_forward(delayed_pkts[j], portid);
                    }
                }
            }
        }
    }
}


static int
rwpa_test_sim_launch_one_lcore(__attribute__((unused)) void *dummy)
{
    rwpa_test_sim_main_loop();
    return 0;
}

/* display usage */
static void
rwpa_test_sim_usage(const char *prgname)
{
    printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
           "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
           "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
           "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
           "  --[no-]mac-updating: Enable or disable MAC addresses updating (enabled by default)\n"
           "      When enabled:\n"
           "       - The source MAC address is replaced by the TX port MAC address\n"
           "       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n"
           "  --mode loopback | gre-and-fwd | delay\n"
           "      - In loopback mode, inner and outer addresses are swapped and packet sent back\n"
           "      - In gre-and-fwd mode, packet is GRE encap'd/decap'd and forwarded\n"
           "      - In delay mode, packet is delayed for duration passed as parameter to --delay-a and --delay-b. Note delay is in microseconds\n"
           "  \t--delay-a VALUE: default packets will be delayed for this VALUE of microseconds. Only true if '--mode delay' is enabled.\n"
           "  \t--delay-b VALUE: specified packets will be delayed for this VALUE of microseconds. Only true if '--mode delay' is enabled.\n"
           "  \t\t--ip-b IP_ADDR: packets with this destination or source IP address will be delayed by delay-b VALUE.\n",
           prgname);
}

static int
rwpa_test_sim_parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

static unsigned int
rwpa_test_sim_parse_nqueue(const char *q_arg)
{
    char *end = NULL;
    unsigned long n;

    /* parse hexadecimal string */
    n = strtoul(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return 0;
    if (n == 0)
        return 0;
    if (n >= MAX_RX_QUEUE_PER_LCORE)
        return 0;

    return n;
}

static int
rwpa_test_sim_parse_timer_period(const char *q_arg)
{
    char *end = NULL;
    int n;

    /* parse number string */
    n = strtol(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;
    if (n >= MAX_TIMER_PERIOD)
        return -1;

    return n;
}

static int
rwpa_test_sim_parse_delay_period(const char *q_arg)
{
    char *end = NULL;
    int n;

    /* parse number string */
    n = strtol(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;
    if (n >= MAX_DELAY_PERIOD)
        return -1;

    return n;
}

#define CMD_LINE_OPT_MODE_LOOPBACK "loopback"
#define CMD_LINE_OPT_MODE_GRE_AND_FWD "gre-and-fwd"
#define CMD_LINE_OPT_MODE_DELAY "delay"

static int
rwpa_test_sim_parse_mode(enum mode *mode, char *optarg)
{
    if (strcmp(CMD_LINE_OPT_MODE_LOOPBACK, optarg) == 0) {
        *mode = MODE_LOOPBACK;
        return 0;
    } else if (strcmp(CMD_LINE_OPT_MODE_GRE_AND_FWD, optarg) == 0) {
        *mode = MODE_GRE_AND_FWD;
        mac_updating = 0;
        return 0;
    } else if (strcmp(CMD_LINE_OPT_MODE_DELAY, optarg) == 0) {
        *mode = MODE_DELAY;
        mac_updating = 0;
        return 0;
    }

    return -1;
}

static const char short_options[] =
    "p:"  /* portmask */
    "q:"  /* number of queues */
    "T:"  /* timer period */
    ;

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
#define CMD_LINE_OPT_MODE "mode"
#define CMD_LINE_OPT_DELAY_A "delay-a"
#define CMD_LINE_OPT_DELAY_B "delay-b"
#define CMD_LINE_OPT_IP_B "ip-b"
#define CMD_LINE_OPT_DELAY_NONE_IP "delay-noneip"

enum {
    /* long options mapped to a short option */

    /* first long only option value must be >= 256, so that we won't
     * conflict with short options */
    CMD_LINE_OPT_MIN_NUM = 256,
};

static struct option lgopts[] = {
    { CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
    { CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
    { CMD_LINE_OPT_MODE, required_argument, 0, 0},
    { CMD_LINE_OPT_DELAY_A, required_argument, 0, 0},
    { CMD_LINE_OPT_DELAY_B, required_argument, 0, 0},
    { CMD_LINE_OPT_IP_B, required_argument, 0, 0},
    { CMD_LINE_OPT_DELAY_NONE_IP, required_argument, 0, 0},
    {NULL, 0, 0, 0}
};

static int
rwpa_test_sim_parse_long_options(struct option *lgopts, int option_index, char *prgname)
{
    int retval, delay_us;

    if (strcmp(lgopts[option_index].name, CMD_LINE_OPT_MODE) == 0) {
        retval = rwpa_test_sim_parse_mode(&mode, optarg);
        return retval;
    }

    if (strcmp(lgopts[option_index].name, "delay-a") == 0) {
        /* Delay Length A */
        delay_us = rwpa_test_sim_parse_delay_period(optarg);
        if (delay_us < 0) {
            printf("invalid Delay-A Length\n");
            rwpa_test_sim_usage(prgname);
            return -1;
        }
        delay_cycles_a = delay_us;
        return 1;
    }

    if (strcmp(lgopts[option_index].name, "delay-b") == 0) {
        /* Delay Length B */
        delay_us = rwpa_test_sim_parse_delay_period(optarg);
        if (delay_us < 0) {
            printf("invalid Delay-B Length\n");
            rwpa_test_sim_usage(prgname);
            return -1;
        }
        delay_cycles_b = delay_us;
        return 1;
    }

    if (strcmp(lgopts[option_index].name, "ip-b") == 0) {
        /* Delay Length B */
        strcpy(delay_b_ip_str, optarg);
        retval = parse_ipv4_addr(optarg, &delay_b_ip_addr);
        if (retval < 0) {
            printf("invalid ip-b args\n");
            rwpa_test_sim_usage(prgname);
            return retval;
        }
        return retval;
    }

    if (strcmp(lgopts[option_index].name, "delay-noneip") == 0) {
        /* Delay Length B */
        strcpy(delay_none_ip_str, optarg);
        retval = parse_ipv4_addr(optarg, &delay_none_ip_addr);
        if (retval < 0) {
            printf("invalid delay-noneip args\n");
            rwpa_test_sim_usage(prgname);
            return retval;
        }
        return retval;
    }

    return -1;
}

/* Parse the argument given in the command line of the application */
static int
rwpa_test_sim_parse_args(int argc, char **argv)
{
    int opt, ret, timer_secs;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    int ret_val;

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, short_options,
                  lgopts, &option_index)) != EOF) {

        switch (opt) {
        /* portmask */
        case 'p':
            rwpa_test_sim_enabled_port_mask = rwpa_test_sim_parse_portmask(optarg);
            if (rwpa_test_sim_enabled_port_mask == 0) {
                printf("invalid portmask\n");
                rwpa_test_sim_usage(prgname);
                return -1;
            }
            break;

        /* nqueue */
        case 'q':
            rwpa_test_sim_rx_queue_per_lcore = rwpa_test_sim_parse_nqueue(optarg);
            if (rwpa_test_sim_rx_queue_per_lcore == 0) {
                printf("invalid queue number\n");
                rwpa_test_sim_usage(prgname);
                return -1;
            }
            break;

        /* timer period */
        case 'T':
            timer_secs = rwpa_test_sim_parse_timer_period(optarg);
            if (timer_secs < 0) {
                printf("invalid timer period\n");
                rwpa_test_sim_usage(prgname);
                return -1;
            }
            timer_period = timer_secs;
            break;

        /* long options */
        case 0:
            ret_val = rwpa_test_sim_parse_long_options(lgopts, option_index, prgname);
            if (ret_val < 0) {
                printf("invalid mode\n");
                       rwpa_test_sim_usage(prgname);
                return -1;
            }
            break;

        default:
            rwpa_test_sim_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind-1] = prgname;

    ret = optind-1;
    optind = 1; /* reset getopt lib */
    return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;
        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++) {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf("Port %d Link Up - speed %u "
                           "Mbps - %s\n", (uint8_t)portid,
                           (unsigned)link.link_speed,
                           (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                           ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n",
                           (uint8_t)portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
               signum);
        force_quit = true;
    }
}

int
main(int argc, char **argv)
{
    struct lcore_queue_conf *qconf;
    struct rte_eth_dev_info dev_info;
    int ret;
    uint8_t nb_ports;
    uint8_t nb_ports_available;
    uint8_t portid, last_port;
    unsigned lcore_id, rx_lcore_id;
    unsigned nb_ports_in_mask = 0;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    arp_store_init();

    /* parse application arguments (after the EAL ones) */
    ret = rwpa_test_sim_parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid RWPA_TEST_SIM arguments\n");

    printf("MAC updating %s\n", mac_updating ? "enabled" : "disabled");

    /* convert to number of cycles */
    timer_period *= rte_get_timer_hz();
    if (mode == MODE_DELAY) {
        printf("Delay Period Default is set to %lu uS\n", delay_cycles_a);
        printf("Delay Period B for IP addr %s is set to %lu uS\n", delay_b_ip_str, delay_cycles_b);
        printf("No delay for IP addr %s\n", delay_none_ip_str);
        delay_cycles_a *= rte_get_timer_hz()/US_PER_S;
        delay_cycles_b *= rte_get_timer_hz()/US_PER_S;
    }

    /* create the mbuf pool */
    rwpa_test_sim_pktmbuf_pool =
        rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
                                MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                rte_socket_id());
    if (rwpa_test_sim_pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    nb_ports = rte_eth_dev_count();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    /* reset rwpa_test_sim_dst_ports */
    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
        rwpa_test_sim_dst_ports[portid] = 0;
    last_port = 0;

    /*
     * Each logical core is assigned a dedicated TX queue on each port.
     */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((rwpa_test_sim_enabled_port_mask & (1 << portid)) == 0)
            continue;

        if (nb_ports_in_mask % 2) {
            rwpa_test_sim_dst_ports[portid] = last_port;
            rwpa_test_sim_dst_ports[last_port] = portid;
        }
        else
            last_port = portid;

        nb_ports_in_mask++;

        rte_eth_dev_info_get(portid, &dev_info);
    }
    if (nb_ports_in_mask % 2) {
        printf("Notice: odd number of ports in portmask.\n");
        rwpa_test_sim_dst_ports[last_port] = last_port;
    }

    rx_lcore_id = 0;
    qconf = NULL;

    /* Initialize the port/queue configuration of each logical core */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((rwpa_test_sim_enabled_port_mask & (1 << portid)) == 0)
            continue;

        /* get the lcore_id for this port */
        while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
               lcore_queue_conf[rx_lcore_id].n_rx_port ==
               rwpa_test_sim_rx_queue_per_lcore) {
            rx_lcore_id++;
            if (rx_lcore_id >= RTE_MAX_LCORE)
                rte_exit(EXIT_FAILURE, "Not enough cores\n");
        }

        if (qconf != &lcore_queue_conf[rx_lcore_id])
            /* Assigned a new logical core in the loop above. */
            qconf = &lcore_queue_conf[rx_lcore_id];

        qconf->rx_port_list[qconf->n_rx_port] = portid;
        qconf->n_rx_port++;
        printf("Lcore %u: RX port %u\n", rx_lcore_id, (unsigned) portid);
    }

    nb_ports_available = nb_ports;

    /* Initialise each port */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((rwpa_test_sim_enabled_port_mask & (1 << portid)) == 0) {
            printf("Skipping disabled port %u\n", (unsigned) portid);
            nb_ports_available--;
            continue;
        }
        /* init port */
        printf("Initializing port %u... ", (unsigned) portid);
        fflush(stdout);
        ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                  ret, (unsigned) portid);

        rte_eth_macaddr_get(portid,&rwpa_test_sim_ports_eth_addr[portid]);

        /* Increase mtu to allow for GRE encapsulated frames. */
        rte_eth_dev_set_mtu(0,2000);
        rte_eth_dev_set_mtu(1,2000);

        /* init one RX queue */
        fflush(stdout);
        ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
                         rte_eth_dev_socket_id(portid),
                         NULL,
                         rwpa_test_sim_pktmbuf_pool);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                  ret, (unsigned) portid);

        /* init one TX queue on each port */
        fflush(stdout);
        ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                                     rte_eth_dev_socket_id(portid),
                                     NULL);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                ret, (unsigned) portid);

        /* Initialize TX buffers */
        tx_buffer[portid] =
            rte_zmalloc_socket("tx_buffer",
                               RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                               rte_eth_dev_socket_id(portid));
        if (tx_buffer[portid] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
                    (unsigned) portid);

        rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

        ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
                                                 rte_eth_tx_buffer_count_callback,
                                                 &port_statistics[portid].dropped);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Cannot set error callback for "
                        "tx buffer on port %u\n", (unsigned) portid);

        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                     ret, (unsigned) portid);

        printf("done: \n");

        rte_eth_promiscuous_enable(portid);

        printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                (unsigned) portid,
                rwpa_test_sim_ports_eth_addr[portid].addr_bytes[0],
                rwpa_test_sim_ports_eth_addr[portid].addr_bytes[1],
                rwpa_test_sim_ports_eth_addr[portid].addr_bytes[2],
                rwpa_test_sim_ports_eth_addr[portid].addr_bytes[3],
                rwpa_test_sim_ports_eth_addr[portid].addr_bytes[4],
                rwpa_test_sim_ports_eth_addr[portid].addr_bytes[5]);

        /* initialize port stats */
        memset(&port_statistics, 0, sizeof(port_statistics));
    }

    if (!nb_ports_available) {
        rte_exit(EXIT_FAILURE,
                 "All available ports are disabled. Please set portmask.\n");
    }

    check_all_ports_link_status(nb_ports, rwpa_test_sim_enabled_port_mask);

    init_ip_wl();

    ret = 0;
    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(rwpa_test_sim_launch_one_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    for (portid = 0; portid < nb_ports; portid++) {
        if ((rwpa_test_sim_enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
    printf("Bye...\n");

    return ret;
}
