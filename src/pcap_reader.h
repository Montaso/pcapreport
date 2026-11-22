/*
 * pcap_reader.h - self-contained reader for classic libpcap (.pcap,
 * micro- and nanosecond, both byte orders) and pcapng files.
 * No libpcap dependency: the formats are simple and parsing them here
 * lets us survive truncated / damaged captures gracefully.
 */
#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <stdint.h>
#include <stdio.h>

/* link-layer types (subset of LINKTYPE_* registry) */
#define LT_NULL       0
#define LT_ETHERNET   1
#define LT_RAW_OLD1   12
#define LT_RAW_OLD2   14
#define LT_RAW        101
#define LT_LOOP       108
#define LT_LINUX_SLL  113
#define LT_IPV4       228
#define LT_IPV6       229
#define LT_LINUX_SLL2 276

#define PR_MAX_IFACES 64

typedef struct {
    double         ts;        /* seconds since epoch */
    uint32_t       caplen;    /* bytes available in data */
    uint32_t       origlen;   /* bytes on the wire */
    int            linktype;
    const uint8_t *data;
} raw_packet_t;

typedef struct {
    FILE    *fp;
    int      is_ng;          /* 0 = classic pcap, 1 = pcapng */
    int      swap;           /* byte order differs from little-endian reading */
    double   ts_mult;        /* classic: 1e-6 or 1e-9 */
    uint32_t linktype;       /* classic */
    uint32_t snaplen;
    /* pcapng interfaces of the current section */
    int      nifs;
    uint16_t if_linktype[PR_MAX_IFACES];
    double   if_tsunit[PR_MAX_IFACES];   /* seconds per timestamp tick */
    int64_t  if_tsoffset[PR_MAX_IFACES];
    uint8_t *buf;
    size_t   bufcap;
    uint64_t truncated;      /* records cut short by end of file */
    char     err[256];
} pcap_reader_t;

int  pr_open(pcap_reader_t *r, const char *path);
/* returns 1 = packet, 0 = end of file, -1 = fatal format error (see r->err) */
int  pr_next(pcap_reader_t *r, raw_packet_t *pkt);
void pr_close(pcap_reader_t *r);
const char *pr_linktype_name(int lt);

#endif
