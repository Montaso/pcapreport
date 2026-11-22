/*
 * decode.h - protocol dissection: link layer -> IPv4/IPv6 -> TCP/UDP/ICMP.
 */
#ifndef DECODE_H
#define DECODE_H

#include "common.h"
#include "pcap_reader.h"

#define IPPROTO_ICMP_   1
#define IPPROTO_TCP_    6
#define IPPROTO_UDP_    17
#define IPPROTO_ICMP6_  58

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

typedef enum {
    L3_NONE = 0,   /* no IP: ARP, LLDP, ... */
    L3_IPV4,
    L3_IPV6,
} l3_kind_t;

typedef struct {
    double   ts;
    uint32_t wire_len;      /* original frame length */
    uint32_t cap_len;
    int      linktype;
    uint16_t ethertype;     /* 0 if unknown */

    l3_kind_t l3;
    addr_t   src, dst;
    uint8_t  proto;         /* IP protocol number */
    uint8_t  ttl;           /* TTL / hop limit */
    uint32_t ip_len;        /* IP datagram length according to header */
    int      is_fragment;   /* non-first fragment: no L4 header available */

    int      has_l4;
    uint16_t sport, dport;
    /* TCP */
    uint8_t  tcp_flags;
    uint32_t seq, ack;
    uint16_t window;
    uint8_t  wscale;        /* window scale option on SYN, 0xFF = absent */
    /* ICMP */
    uint8_t  icmp_type, icmp_code;

    uint32_t payload_len;   /* L4 payload length from headers */
    const uint8_t *payload; /* captured payload bytes */
    uint32_t payload_cap;

    int      truncated;     /* capture shorter than headers claim */
    int      malformed;     /* header values impossible */
    int      unsupported_link;
} pkt_t;

/* returns 0 on success (pkt filled, possibly l3 == L3_NONE) */
int decode_packet(const raw_packet_t *raw, pkt_t *pkt);

#endif
