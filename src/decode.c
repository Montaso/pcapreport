#include "decode.h"

#include <string.h>

#define ETH_IPV4 0x0800
#define ETH_IPV6 0x86DD
#define ETH_VLAN 0x8100
#define ETH_QINQ 0x88A8
#define ETH_QINQ_OLD 0x9100

static void decode_l4(pkt_t *p, const uint8_t *d, uint32_t avail, uint32_t l4len)
{
    /* d points at L4 header; avail = captured bytes, l4len = bytes per IP header */
    if (p->is_fragment) return;

    if (p->proto == IPPROTO_TCP_) {
        if (avail < 20) { p->truncated = 1; return; }
        uint32_t doff = (uint32_t)(d[12] >> 4) * 4;
        if (doff < 20 || doff > l4len) { p->malformed = 1; return; }
        p->has_l4 = 1;
        p->sport = rd16be(d);
        p->dport = rd16be(d + 2);
        p->seq = rd32be(d + 4);
        p->ack = rd32be(d + 8);
        p->tcp_flags = d[13];
        p->window = rd16be(d + 14);
        p->wscale = 0xFF;
        if (doff > avail) { p->truncated = 1; doff = avail < 20 ? 20 : doff; }
        /* options: only window scale is of interest */
        if (p->tcp_flags & TCP_SYN) {
            uint32_t o = 20, end = MIN(doff, avail);
            while (o < end) {
                uint8_t kind = d[o];
                if (kind == 0) break;
                if (kind == 1) { o++; continue; }
                if (o + 1 >= end) break;
                uint8_t len = d[o + 1];
                if (len < 2 || o + len > end) break;
                if (kind == 3 && len == 3) p->wscale = d[o + 2];
                o += len;
            }
        }
        p->payload_len = l4len - doff;
        p->payload = avail > doff ? d + doff : NULL;
        p->payload_cap = avail > doff ? MIN(avail - doff, p->payload_len) : 0;
    } else if (p->proto == IPPROTO_UDP_) {
        if (avail < 8) { p->truncated = 1; return; }
        p->has_l4 = 1;
        p->sport = rd16be(d);
        p->dport = rd16be(d + 2);
        uint32_t ulen = rd16be(d + 4);
        if (ulen < 8 || ulen > l4len) {
            /* jumbograms use 0; otherwise trust the IP layer */
            if (ulen != 0) p->malformed = 1;
            ulen = l4len;
        }
        p->payload_len = ulen >= 8 ? ulen - 8 : 0;
        p->payload = avail > 8 ? d + 8 : NULL;
        p->payload_cap = avail > 8 ? MIN(avail - 8, p->payload_len) : 0;
    } else if (p->proto == IPPROTO_ICMP_ || p->proto == IPPROTO_ICMP6_) {
        if (avail < 4) { p->truncated = 1; return; }
        p->icmp_type = d[0];
        p->icmp_code = d[1];
        p->payload_len = l4len >= 4 ? l4len - 4 : 0;
    }
}

static void decode_ipv4(pkt_t *p, const uint8_t *d, uint32_t avail)
{
    if (avail < 20) { p->truncated = 1; return; }
    if ((d[0] >> 4) != 4) { p->malformed = 1; return; }
    uint32_t ihl = (uint32_t)(d[0] & 0x0F) * 4;
    uint32_t tot = rd16be(d + 2);
    if (ihl < 20) { p->malformed = 1; return; }
    if (tot == 0) tot = avail;             /* TSO / offloaded captures */
    if (tot < ihl) { p->malformed = 1; return; }
    p->l3 = L3_IPV4;
    p->src.ver = p->dst.ver = 4;
    memcpy(p->src.a, d + 12, 4);
    memcpy(p->dst.a, d + 16, 4);
    p->proto = d[9];
    p->ttl = d[8];
    p->ip_len = tot;
    uint16_t frag = rd16be(d + 6);
    if (frag & 0x1FFF) p->is_fragment = 1;
    if (ihl > avail) { p->truncated = 1; return; }
    uint32_t cap = MIN(avail, tot);
    if (avail < tot) p->truncated = 1;
    decode_l4(p, d + ihl, cap - ihl, tot - ihl);
}

static int ipv6_is_ext(uint8_t nh)
{
    return nh == 0 || nh == 43 || nh == 44 || nh == 60 || nh == 51 || nh == 135;
}

static void decode_ipv6(pkt_t *p, const uint8_t *d, uint32_t avail)
{
    if (avail < 40) { p->truncated = 1; return; }
    if ((d[0] >> 4) != 6) { p->malformed = 1; return; }
    p->l3 = L3_IPV6;
    p->src.ver = p->dst.ver = 6;
    memcpy(p->src.a, d + 8, 16);
    memcpy(p->dst.a, d + 24, 16);
    p->ttl = d[7];
    uint32_t plen = rd16be(d + 4);
    if (plen == 0) plen = avail - 40;     /* jumbo or offload */
    p->ip_len = plen + 40;
    if (avail < p->ip_len) p->truncated = 1;
    uint32_t cap = MIN(avail, p->ip_len);

    uint8_t nh = d[6];
    uint32_t off = 40;
    int guard = 0;
    while (ipv6_is_ext(nh) && guard++ < 8) {
        if (off + 8 > cap) { p->truncated = 1; p->proto = nh; return; }
        uint8_t next = d[off];
        uint32_t len;
        if (nh == 44) {                      /* fragment header */
            uint16_t fo = rd16be(d + off + 2);
            if (fo & 0xFFF8) p->is_fragment = 1;
            len = 8;
        } else if (nh == 51) {
            len = ((uint32_t)d[off + 1] + 2) * 4;
        } else {
            len = ((uint32_t)d[off + 1] + 1) * 8;
        }
        nh = next;
        off += len;
    }
    p->proto = nh;
    if (off > cap) { p->truncated = 1; return; }
    if (off > p->ip_len) { p->malformed = 1; return; }
    decode_l4(p, d + off, cap - off, p->ip_len - off);
}

int decode_packet(const raw_packet_t *raw, pkt_t *p)
{
    memset(p, 0, sizeof *p);
    p->ts = raw->ts;
    p->wire_len = raw->origlen;
    p->cap_len = raw->caplen;
    p->linktype = raw->linktype;

    const uint8_t *d = raw->data;
    uint32_t n = raw->caplen;
    uint32_t off = 0;
    uint16_t et = 0;

    switch (raw->linktype) {
    case LT_ETHERNET:
        if (n < 14) { p->truncated = 1; return 0; }
        et = rd16be(d + 12);
        off = 14;
        while ((et == ETH_VLAN || et == ETH_QINQ || et == ETH_QINQ_OLD) && off + 4 <= n) {
            et = rd16be(d + off + 2);
            off += 4;
        }
        break;
    case LT_LINUX_SLL:
        if (n < 16) { p->truncated = 1; return 0; }
        et = rd16be(d + 14);
        off = 16;
        break;
    case LT_LINUX_SLL2:
        if (n < 20) { p->truncated = 1; return 0; }
        et = rd16be(d);
        off = 20;
        break;
    case LT_NULL:
    case LT_LOOP: {
        if (n < 4) { p->truncated = 1; return 0; }
        uint32_t fam = raw->linktype == LT_LOOP ? rd32be(d) : rd32le(d);
        if (fam > 0xFFFF) fam = rd32be(d);           /* other host byte order */
        if (fam == 2) et = ETH_IPV4;
        else if (fam == 24 || fam == 28 || fam == 30 || fam == 10) et = ETH_IPV6;
        off = 4;
        break;
    }
    case LT_RAW:
    case LT_RAW_OLD1:
    case LT_RAW_OLD2:
    case LT_IPV4:
    case LT_IPV6:
        if (n < 1) { p->truncated = 1; return 0; }
        et = (d[0] >> 4) == 6 ? ETH_IPV6 : (d[0] >> 4) == 4 ? ETH_IPV4 : 0;
        off = 0;
        break;
    default:
        p->unsupported_link = 1;
        return 0;
    }
    p->ethertype = et;
    if (off > n) { p->truncated = 1; return 0; }

    if (et == ETH_IPV4) decode_ipv4(p, d + off, n - off);
    else if (et == ETH_IPV6) decode_ipv6(p, d + off, n - off);
    return 0;
}
