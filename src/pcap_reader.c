#include "pcap_reader.h"
#include "common.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#define PCAPNG_SHB 0x0A0D0D0Au
#define PCAPNG_IDB 0x00000001u
#define PCAPNG_OPB 0x00000002u /* obsolete packet block */
#define PCAPNG_SPB 0x00000003u
#define PCAPNG_EPB 0x00000006u

#define MAX_BLOCK (64u * 1024u * 1024u)

static uint16_t r16(const pcap_reader_t *r, const uint8_t *p) { return r->swap ? rd16be(p) : rd16le(p); }
static uint32_t r32(const pcap_reader_t *r, const uint8_t *p) { return r->swap ? rd32be(p) : rd32le(p); }

static int ensure_buf(pcap_reader_t *r, size_t n)
{
    if (n > r->bufcap) {
        size_t c = r->bufcap ? r->bufcap : 65536;
        while (c < n) c *= 2;
        r->buf = xrealloc(r->buf, c);
        r->bufcap = c;
    }
    return 0;
}

const char *pr_linktype_name(int lt)
{
    switch (lt) {
    case LT_NULL: return "BSD loopback (NULL)";
    case LT_ETHERNET: return "Ethernet";
    case LT_RAW: case LT_RAW_OLD1: case LT_RAW_OLD2: return "Raw IP";
    case LT_LOOP: return "OpenBSD loopback";
    case LT_LINUX_SLL: return "Linux cooked (SLL)";
    case LT_LINUX_SLL2: return "Linux cooked v2 (SLL2)";
    case LT_IPV4: return "Raw IPv4";
    case LT_IPV6: return "Raw IPv6";
    default: return "nieobsługiwany";
    }
}

/* ---------------------------------------------------------------- pcapng */

static void ng_parse_idb(pcap_reader_t *r, const uint8_t *body, uint32_t blen)
{
    if (r->nifs >= PR_MAX_IFACES || blen < 8) return;
    int i = r->nifs++;
    r->if_linktype[i] = r16(r, body);
    r->if_tsunit[i] = 1e-6;
    r->if_tsoffset[i] = 0;
    uint32_t off = 8;
    while (off + 4 <= blen) {
        uint16_t code = r16(r, body + off);
        uint16_t len = r16(r, body + off + 2);
        off += 4;
        if (code == 0 || off + len > blen) break;
        if (code == 9 && len >= 1) {               /* if_tsresol */
            uint8_t v = body[off];
            if (v & 0x80) r->if_tsunit[i] = ldexp(1.0, -(int)(v & 0x7F));
            else r->if_tsunit[i] = pow(10.0, -(double)v);
        } else if (code == 14 && len >= 8) {       /* if_tsoffset */
            uint64_t lo = r32(r, body + off), hi = r32(r, body + off + 4);
            r->if_tsoffset[i] = (int64_t)(r->swap ? (lo << 32) | hi : (hi << 32) | lo);
        }
        off += (uint32_t)((len + 3u) & ~3u);
    }
}

/* reads one whole block into r->buf; returns body pointer via *body */
static int ng_read_block(pcap_reader_t *r, uint32_t *type, const uint8_t **body, uint32_t *blen)
{
    uint8_t hdr[8];
    size_t n = fread(hdr, 1, 8, r->fp);
    if (n == 0) return 0;
    if (n < 8) { r->truncated++; return 0; }

    uint32_t t = r32(r, hdr);
    if (t == PCAPNG_SHB) {
        /* new section: byte order may change */
        uint8_t bom[4];
        if (fread(bom, 1, 4, r->fp) < 4) { r->truncated++; return 0; }
        uint32_t m = rd32le(bom);
        if (m == 0x1A2B3C4Du) r->swap = 0;
        else if (m == 0x4D3C2B1Au) r->swap = 1;
        else { snprintf(r->err, sizeof r->err, "niepoprawny znacznik kolejności bajtów pcapng"); return -1; }
        uint32_t len = r32(r, hdr + 4);
        if (len < 28 || len > MAX_BLOCK || (len & 3)) {
            snprintf(r->err, sizeof r->err, "niepoprawna długość bloku SHB (%u)", len);
            return -1;
        }
        ensure_buf(r, len);
        memcpy(r->buf, bom, 4);
        if (fread(r->buf + 4, 1, len - 12, r->fp) < len - 12) { r->truncated++; return 0; }
        r->nifs = 0;
        *type = t;
        *body = r->buf;
        *blen = len - 12;
        return 1;
    }

    uint32_t len = r32(r, hdr + 4);
    if (len < 12 || len > MAX_BLOCK || (len & 3)) {
        snprintf(r->err, sizeof r->err, "niepoprawna długość bloku pcapng (%u)", len);
        return -1;
    }
    ensure_buf(r, len);
    size_t want = len - 8;
    if (fread(r->buf, 1, want, r->fp) < want) { r->truncated++; return 0; }
    *type = t;
    *body = r->buf;
    *blen = len - 12;
    return 1;
}

static int ng_next(pcap_reader_t *r, raw_packet_t *pkt)
{
    for (;;) {
        uint32_t type, blen;
        const uint8_t *b;
        int rc = ng_read_block(r, &type, &b, &blen);
        if (rc <= 0) return rc;

        if (type == PCAPNG_IDB) { ng_parse_idb(r, b, blen); continue; }
        if (type == PCAPNG_EPB || type == PCAPNG_OPB) {
            if (blen < 20) continue;
            uint32_t ifid, hi, lo, cap, orig;
            if (type == PCAPNG_EPB) {
                ifid = r32(r, b);
                hi = r32(r, b + 4); lo = r32(r, b + 8);
                cap = r32(r, b + 12); orig = r32(r, b + 16);
            } else {
                ifid = r16(r, b);
                hi = r32(r, b + 4); lo = r32(r, b + 8);
                cap = r32(r, b + 12); orig = r32(r, b + 16);
            }
            if (cap > blen - 20) cap = blen - 20;
            double unit = 1e-6;
            int64_t toff = 0;
            int lt = LT_ETHERNET;
            if (ifid < (uint32_t)r->nifs) {
                unit = r->if_tsunit[ifid];
                toff = r->if_tsoffset[ifid];
                lt = r->if_linktype[ifid];
            }
            uint64_t raw = ((uint64_t)hi << 32) | lo;
            pkt->ts = (double)raw * unit + (double)toff;
            pkt->caplen = cap;
            pkt->origlen = orig < cap ? cap : orig;
            pkt->linktype = lt;
            pkt->data = b + 20;
            return 1;
        }
        if (type == PCAPNG_SPB) {
            if (blen < 4) continue;
            uint32_t orig = r32(r, b);
            uint32_t cap = MIN(orig, blen - 4);
            pkt->ts = 0;  /* simple packet blocks carry no timestamp */
            pkt->caplen = cap;
            pkt->origlen = orig;
            pkt->linktype = r->nifs ? r->if_linktype[0] : LT_ETHERNET;
            pkt->data = b + 4;
            return 1;
        }
        /* other blocks (NRB, ISB, custom ...) are skipped */
    }
}

/* ---------------------------------------------------------------- classic */

static int classic_next(pcap_reader_t *r, raw_packet_t *pkt)
{
    uint8_t h[16];
    size_t n = fread(h, 1, 16, r->fp);
    if (n == 0) return 0;
    if (n < 16) { r->truncated++; return 0; }
    uint32_t sec = r32(r, h), frac = r32(r, h + 4);
    uint32_t cap = r32(r, h + 8), orig = r32(r, h + 12);
    if (cap > MAX_BLOCK) {
        snprintf(r->err, sizeof r->err, "uszkodzony rekord pakietu (caplen=%u)", cap);
        return -1;
    }
    ensure_buf(r, cap ? cap : 1);
    size_t got = fread(r->buf, 1, cap, r->fp);
    if (got < cap) {
        r->truncated++;
        return 0;
    }
    pkt->ts = (double)sec + (double)frac * r->ts_mult;
    pkt->caplen = cap;
    pkt->origlen = orig < cap ? cap : orig;
    pkt->linktype = (int)r->linktype;
    pkt->data = r->buf;
    return 1;
}

/* ---------------------------------------------------------------- API */

int pr_open(pcap_reader_t *r, const char *path)
{
    memset(r, 0, sizeof *r);
    r->fp = fopen(path, "rb");
    if (!r->fp) { snprintf(r->err, sizeof r->err, "nie można otworzyć pliku"); return -1; }

    uint8_t h[24];
    if (fread(h, 1, 4, r->fp) < 4) { snprintf(r->err, sizeof r->err, "plik jest pusty lub za krótki"); return -1; }
    uint32_t m = rd32le(h);
    if (m == PCAPNG_SHB) {
        r->is_ng = 1;
        rewind(r->fp);
        return 0;
    }
    if (fread(h + 4, 1, 20, r->fp) < 20) { snprintf(r->err, sizeof r->err, "niekompletny nagłówek pcap"); return -1; }
    switch (m) {
    case 0xA1B2C3D4u: r->swap = 0; r->ts_mult = 1e-6; break;
    case 0xD4C3B2A1u: r->swap = 1; r->ts_mult = 1e-6; break;
    case 0xA1B23C4Du: r->swap = 0; r->ts_mult = 1e-9; break;
    case 0x4D3CB2A1u: r->swap = 1; r->ts_mult = 1e-9; break;
    default:
        snprintf(r->err, sizeof r->err, "nieznany format pliku (magic 0x%08X) - oczekiwano pcap/pcapng", m);
        return -1;
    }
    r->snaplen = r32(r, h + 16);
    r->linktype = r32(r, h + 20) & 0xFFFF;
    return 0;
}

int pr_next(pcap_reader_t *r, raw_packet_t *pkt)
{
    return r->is_ng ? ng_next(r, pkt) : classic_next(r, pkt);
}

void pr_close(pcap_reader_t *r)
{
    if (r->fp) fclose(r->fp);
    free(r->buf);
    r->fp = NULL;
    r->buf = NULL;
}
