/*
 * analyzer.h - traffic statistics, bidirectional flow tracking (TCP/UDP),
 * host and service accounting, DNS inspection and a traffic timeline.
 */
#ifndef ANALYZER_H
#define ANALYZER_H

#include "common.h"
#include "decode.h"
#include "hmap.h"

enum { P_TCP = 0, P_UDP, P_ICMP, P_OTHER_IP, P_NON_IP, P_COUNT };
extern const char *const PROTO_NAMES[P_COUNT];

/* packet size histogram bins (frame length on the wire) */
#define SIZE_BINS 7
extern const char *const SIZE_BIN_LABELS[SIZE_BINS];

/* timeline series */
enum { TL_TCP = 0, TL_UDP, TL_OTHER, TL_COUNT };

/* final TCP connection classification */
typedef enum {
    TCS_CLOSED_FIN = 0, /* handshake + FIN in both directions */
    TCS_OPEN,           /* handshake done, never closed in capture */
    TCS_RESET,          /* handshake done, terminated with RST */
    TCS_REJECTED,       /* SYN answered with RST */
    TCS_NO_REPLY,       /* SYN never answered */
    TCS_HALF_OPEN,      /* SYN + SYN/ACK, final ACK missing */
    TCS_MIDSTREAM,      /* capture started after the handshake */
    TCS_COUNT
} tcp_cstate_t;
extern const char *const TCS_NAMES[TCS_COUNT];

/* TCP flag statistics */
enum { F_SYN = 0, F_SYNACK, F_ACK, F_PSH, F_FIN, F_RST, F_URG, F_ECE_CWR, F_COUNT };
extern const char *const FLAG_NAMES[F_COUNT];
/* invalid flag combinations */
enum { BF_NULL = 0, BF_XMAS, BF_SYNFIN, BF_SYNRST, BF_COUNT };
extern const char *const BADFLAG_NAMES[BF_COUNT];

typedef struct {
    uint64_t pkts, bytes;
} counter_t;

typedef struct {
    uint8_t  proto;          /* IPPROTO_TCP_ / IPPROTO_UDP_ */
    addr_t   cli, srv;       /* initiator / responder */
    uint16_t cport, sport;
    double   first, last;
    uint64_t pkts[2];        /* [0] client->server, [1] server->client */
    uint64_t bytes[2];       /* wire bytes */
    uint64_t payload[2];     /* L4 payload bytes */

    /* TCP only */
    uint8_t  flags_seen[2];
    uint8_t  syn_seen, synack_seen, hs_done, fin[2], rst[2];
    uint8_t  bad_flags;      /* bitmask of BF_* seen */
    uint8_t  seq_valid[2];
    uint8_t  state;          /* tcp_cstate_t, computed in analysis_finish */
    uint32_t next_seq[2];
    uint32_t syn_count;      /* SYNs without ACK (repeated SYN = retry) */
    uint32_t data_segs[2];
    uint32_t retrans[2];
    uint32_t ooo[2];         /* segments beyond expected seq (loss before capture point) */
    uint32_t zero_win[2];
    double   syn_ts, synack_ts;
    double   rtt;            /* SYN -> SYN/ACK in seconds, < 0 if unknown */
} flow_t;

typedef struct {
    addr_t   a;
    uint64_t pkts_tx, pkts_rx, bytes_tx, bytes_rx;
    uint32_t flows_cli, flows_srv;
    uint64_t syn_tx, syn_rx, rst_tx, icmp_unreach_tx;
    uint64_t bad_flags_tx;
    double   first_syn_rx, last_syn_rx;
} host_t;

typedef struct {
    uint8_t  proto;
    uint16_t port;
    uint32_t flows;
    uint64_t pkts, bytes;
} service_t;

typedef struct {
    char    *name;
    uint32_t queries;
    uint32_t nxdomain;
    addr_t   first_client;
    double   entropy;        /* Shannon entropy of the longest label */
    uint16_t longest_label;
} dns_name_t;

typedef struct {
    char    *path;
    int      is_ng;
    int      linktype;       /* first linktype seen */
    uint64_t packets;
    uint64_t bytes;
    uint64_t truncated_records;
    int      error;          /* 1 if reading stopped on error */
    char     errmsg[256];
} file_info_t;

typedef struct {
    /* input files */
    file_info_t *files;
    int          nfiles;
    size_t       cfiles;

    /* global counters */
    uint64_t packets, bytes, cap_bytes;
    double   first_ts, last_ts;
    counter_t proto[P_COUNT];
    counter_t ipv4, ipv6;
    uint64_t truncated, malformed, fragments, unsupported_link, zero_ts;
    uint64_t arp;
    uint64_t size_hist[2][SIZE_BINS];   /* [0] TCP, [1] UDP */
    uint32_t min_len, max_len;
    uint64_t ttl_hist[256];

    /* timeline */
    double   tl_t0, tl_bucket;
    int      tl_n;
    double  *tl_bytes[TL_COUNT];
    double  *tl_pkts[TL_COUNT];

    /* TCP */
    uint64_t flag_count[F_COUNT];
    uint64_t bad_flags[BF_COUNT];
    uint64_t tcp_retrans, tcp_data_segs, tcp_ooo, tcp_zero_win;
    uint64_t tcs_count[TCS_COUNT];

    /* flows */
    flow_t  *flows;
    size_t   nflows, cflows;
    hmap_t   flowmap;
    uint64_t tcp_flows, udp_flows;

    /* hosts & services */
    host_t  *hosts;
    size_t   nhosts, chosts;
    hmap_t   hostmap;
    service_t *svcs;
    size_t   nsvcs, csvcs;

    /* DNS */
    uint64_t dns_queries, dns_responses, dns_nxdomain, dns_servfail, dns_other_err, dns_malformed;
    dns_name_t *dns_names;
    size_t   ndns, cdns;
    hmap_t   dnsmap;

    /* ICMP */
    uint64_t icmp_unreach, icmp_echo_req, icmp_echo_rep, icmp_ttl_exceeded;
} analysis_t;

typedef struct {
    double bucket;           /* forced timeline bucket width (s), 0 = auto */
    double flow_timeout;     /* idle timeout that splits flows (s) */
} analysis_opts_t;

/* pass 1: find time span of all inputs (returns number of packets) */
uint64_t analysis_prescan(char **paths, int n, double *t0, double *t1);
void analysis_init(analysis_t *an, double t0, double t1, const analysis_opts_t *o);
/* pass 2: reads a whole file into the analysis; returns 0 on success */
int  analysis_add_file(analysis_t *an, const char *path, const analysis_opts_t *o);
/* post-processing: classification, services, sorting helpers */
void analysis_finish(analysis_t *an);
void analysis_free(analysis_t *an);

/* helpers */
host_t *analysis_host(analysis_t *an, const addr_t *a);  /* lookup only, may be NULL */
const char *service_name(uint8_t proto, uint16_t port);
int  flow_is_failed_attempt(const flow_t *f);
uint64_t flow_total_bytes(const flow_t *f);
uint64_t flow_total_pkts(const flow_t *f);

#endif
