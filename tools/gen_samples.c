/*
 * gen_samples.c - generator syntetycznych plików przechwytu do testów
 * narzędzia pcapreport. Tworzy:
 *   normal.pcap    - typowy ruch biurowy (DNS, HTTPS, HTTP, SSH, QUIC, NTP, ICMP, ARP)
 *   attacks.pcap   - ruch z atakami (skanowania, SYN/UDP flood, tunel DNS, DGA,
 *                    beaconing, telnet, reverse shell, eksfiltracja, retransmisje)
 *   mixed.pcapng   - pcapng z dwoma interfejsami (Ethernet+VLAN, raw IP),
 *                    znaczniki nanosekundowe, IPv6, snaplen 128 (obcięte pakiety)
 * Wynik jest deterministyczny (stałe ziarno PRNG).
 *
 * Użycie: gen_samples KATALOG
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ PRNG */

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 16);
}
static double rndf(void) { return (rnd() & 0xFFFFFF) / (double)0x1000000; }
static uint32_t rndr(uint32_t lo, uint32_t hi) { return lo + rnd() % (hi - lo + 1); }

/* ------------------------------------------------------------------ packet store */

typedef struct {
    double   ts;
    int      iface;
    uint32_t len;
    uint8_t *data;
    uint64_t seq;
} rec_t;

static rec_t *recs;
static size_t nrecs, crecs;

static void store(double ts, int iface, const uint8_t *d, uint32_t len)
{
    if (nrecs == crecs) {
        crecs = crecs ? crecs * 2 : 4096;
        recs = realloc(recs, crecs * sizeof *recs);
        if (!recs) { perror("realloc"); exit(1); }
    }
    rec_t *r = &recs[nrecs];
    r->ts = ts;
    r->iface = iface;
    r->len = len;
    r->data = malloc(len);
    if (!r->data) { perror("malloc"); exit(1); }
    memcpy(r->data, d, len);
    r->seq = nrecs++;
}

static int cmp_rec(const void *a, const void *b)
{
    const rec_t *x = a, *y = b;
    if (x->ts != y->ts) return x->ts < y->ts ? -1 : 1;
    return x->seq < y->seq ? -1 : 1;
}

static void clear_store(void)
{
    for (size_t i = 0; i < nrecs; i++) free(recs[i].data);
    nrecs = 0;
}

static void put16le(FILE *f, uint16_t v) { fputc(v & 0xFF, f); fputc(v >> 8, f); }
static void put32le(FILE *f, uint32_t v) { for (int i = 0; i < 4; i++) fputc((v >> (8 * i)) & 0xFF, f); }

static void write_pcap(const char *path, uint32_t linktype, uint32_t snaplen)
{
    qsort(recs, nrecs, sizeof *recs, cmp_rec);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    put32le(f, 0xA1B2C3D4);
    put16le(f, 2); put16le(f, 4);
    put32le(f, 0); put32le(f, 0);
    put32le(f, snaplen);
    put32le(f, linktype);
    for (size_t i = 0; i < nrecs; i++) {
        rec_t *r = &recs[i];
        uint32_t sec = (uint32_t)r->ts;
        uint32_t usec = (uint32_t)((r->ts - sec) * 1e6 + 0.5);
        if (usec >= 1000000) { sec++; usec -= 1000000; }
        uint32_t cap = r->len < snaplen ? r->len : snaplen;
        put32le(f, sec); put32le(f, usec); put32le(f, cap); put32le(f, r->len);
        fwrite(r->data, 1, cap, f);
    }
    fclose(f);
    printf("  %s: %zu pakietów\n", path, nrecs);
    clear_store();
}

/* pcapng writer: interfaces 0 = Ethernet, 1 = raw IP; nanosecond timestamps */
static void ng_block(FILE *f, uint32_t type, const uint8_t *body, uint32_t blen)
{
    uint32_t pad = (4 - (blen & 3)) & 3;
    uint32_t total = 12 + blen + pad;
    put32le(f, type);
    put32le(f, total);
    fwrite(body, 1, blen, f);
    for (uint32_t i = 0; i < pad; i++) fputc(0, f);
    put32le(f, total);
}

static void write_pcapng(const char *path, uint32_t snaplen)
{
    qsort(recs, nrecs, sizeof *recs, cmp_rec);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    uint8_t b[4096];
    /* SHB: BOM, version 1.0, section length -1 */
    uint8_t shb[16] = {0x4D, 0x3C, 0x2B, 0x1A, 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ng_block(f, 0x0A0D0D0A, shb, 16);
    for (int ifc = 0; ifc < 2; ifc++) {
        uint32_t n = 0;
        uint16_t lt = ifc == 0 ? 1 : 101;
        b[n++] = lt & 0xFF; b[n++] = lt >> 8; b[n++] = 0; b[n++] = 0;
        memcpy(b + n, &snaplen, 4); n += 4;       /* host is little-endian in practice */
        /* if_tsresol = 9 (nanoseconds) */
        b[n++] = 9; b[n++] = 0; b[n++] = 1; b[n++] = 0; b[n++] = 9; b[n++] = 0; b[n++] = 0; b[n++] = 0;
        /* opt_endofopt */
        b[n++] = 0; b[n++] = 0; b[n++] = 0; b[n++] = 0;
        ng_block(f, 1, b, n);
    }
    uint8_t *body = malloc(65536 + 64);
    for (size_t i = 0; i < nrecs; i++) {
        rec_t *r = &recs[i];
        uint64_t ns = (uint64_t)(r->ts * 1e9);
        uint32_t cap = r->len < snaplen ? r->len : snaplen;
        uint32_t v[5] = {(uint32_t)r->iface, (uint32_t)(ns >> 32), (uint32_t)ns, cap, r->len};
        memcpy(body, v, 20);
        memcpy(body + 20, r->data, cap);
        ng_block(f, 6, body, 20 + cap);
    }
    free(body);
    fclose(f);
    printf("  %s: %zu pakietów\n", path, nrecs);
    clear_store();
}

/* ------------------------------------------------------------------ packet building */

typedef struct {
    int     v6;
    uint8_t a[16];
} ip_t;

static ip_t ip4(int a, int b, int c, int d)
{
    ip_t r = {0};
    r.a[0] = (uint8_t)a; r.a[1] = (uint8_t)b; r.a[2] = (uint8_t)c; r.a[3] = (uint8_t)d;
    return r;
}

static ip_t ip6(uint16_t g0, uint16_t g1, uint16_t g6, uint16_t g7)
{
    ip_t r = {0};
    r.v6 = 1;
    uint16_t g[8] = {g0, g1, 0, 0, 0, 0, g6, g7};
    for (int i = 0; i < 8; i++) { r.a[2 * i] = (uint8_t)(g[i] >> 8); r.a[2 * i + 1] = (uint8_t)g[i]; }
    return r;
}

static void w16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void w32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

static uint32_t csum_add(uint32_t s, const uint8_t *d, size_t n)
{
    for (size_t i = 0; i + 1 < n; i += 2) s += (uint32_t)(d[i] << 8 | d[i + 1]);
    if (n & 1) s += (uint32_t)(d[n - 1] << 8);
    return s;
}
static uint16_t csum_fin(uint32_t s)
{
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)~s;
}

/* output mode for the next packets */
static int g_iface = 0;        /* 0 = Ethernet, 1 = raw IP */
static int g_vlan = 0;         /* 802.1Q tag for Ethernet frames */
static uint8_t g_ttl = 64;
static uint16_t g_ipid = 1;

static uint8_t pktbuf[70000];

/* emit IP packet with given L4 header+payload */
static void emit_ip(double ts, ip_t src, ip_t dst, uint8_t proto, const uint8_t *l4, uint32_t l4len, int csum_off)
{
    uint8_t *p = pktbuf;
    uint32_t off = 0;
    if (g_iface == 0) {
        static const uint8_t mac_a[6] = {0x00, 0x1b, 0x21, 0x3a, 0x4f, 0x01};
        static const uint8_t mac_b[6] = {0x00, 0x50, 0x56, 0xc0, 0x00, 0x08};
        int dir = memcmp(src.a, dst.a, 16) < 0;
        memcpy(p, dir ? mac_a : mac_b, 6);
        memcpy(p + 6, dir ? mac_b : mac_a, 6);
        off = 12;
        if (g_vlan) { w16(p + off, 0x8100); w16(p + off + 2, (uint16_t)g_vlan); off += 4; }
        w16(p + off, src.v6 ? 0x86DD : 0x0800);
        off += 2;
    }
    uint8_t *ip = p + off;
    uint32_t iphl;
    if (!src.v6) {
        iphl = 20;
        memset(ip, 0, 20);
        ip[0] = 0x45;
        w16(ip + 2, (uint16_t)(20 + l4len));
        w16(ip + 4, g_ipid++);
        w16(ip + 6, 0x4000);
        ip[8] = g_ttl;
        ip[9] = proto;
        memcpy(ip + 12, src.a, 4);
        memcpy(ip + 16, dst.a, 4);
        w16(ip + 10, csum_fin(csum_add(0, ip, 20)));
    } else {
        iphl = 40;
        memset(ip, 0, 40);
        ip[0] = 0x60;
        w16(ip + 4, (uint16_t)l4len);
        ip[6] = proto;
        ip[7] = g_ttl;
        memcpy(ip + 8, src.a, 16);
        memcpy(ip + 24, dst.a, 16);
    }
    uint8_t *l = ip + iphl;
    memcpy(l, l4, l4len);
    if (csum_off >= 0) {
        uint32_t s = 0;
        uint8_t ph[40];
        if (!src.v6) {
            memcpy(ph, src.a, 4); memcpy(ph + 4, dst.a, 4);
            ph[8] = 0; ph[9] = proto; w16(ph + 10, (uint16_t)l4len);
            s = csum_add(0, ph, 12);
        } else {
            s = csum_add(0, src.a, 16);
            s = csum_add(s, dst.a, 16);
            s += l4len;
            s += proto;
        }
        l[csum_off] = l[csum_off + 1] = 0;
        s = csum_add(s, l, l4len);
        uint16_t c = csum_fin(s);
        w16(l + csum_off, c);
    }
    store(ts, g_iface, p, off + iphl + l4len);
}

static uint8_t l4buf[70000];

static void fill_payload(uint8_t *d, uint32_t n, const char *text)
{
    if (text) {
        size_t tl = strlen(text);
        for (uint32_t i = 0; i < n; i++) d[i] = (uint8_t)text[i % tl];
    } else {
        for (uint32_t i = 0; i < n; i++) d[i] = (uint8_t)rnd();
    }
}

static void tcp_pkt(double ts, ip_t s, uint16_t sp, ip_t d, uint16_t dp, uint32_t seq, uint32_t ack, uint8_t flags,
                    uint16_t win, uint32_t plen, const char *text)
{
    uint8_t *t = l4buf;
    int syn = flags & 0x02;
    uint32_t hl = syn ? 24 : 20;
    memset(t, 0, hl);
    w16(t, sp);
    w16(t + 2, dp);
    w32(t + 4, seq);
    w32(t + 8, ack);
    t[12] = (uint8_t)((hl / 4) << 4);
    t[13] = flags;
    w16(t + 14, win);
    if (syn) { t[20] = 2; t[21] = 4; w16(t + 22, 1460); }  /* MSS option */
    fill_payload(t + hl, plen, text);
    emit_ip(ts, s, d, 6, t, hl + plen, 16);
}

static void udp_pkt(double ts, ip_t s, uint16_t sp, ip_t d, uint16_t dp, const uint8_t *pl, uint32_t plen)
{
    uint8_t *u = l4buf;
    w16(u, sp);
    w16(u + 2, dp);
    w16(u + 4, (uint16_t)(8 + plen));
    w16(u + 6, 0);
    if (pl) memcpy(u + 8, pl, plen);
    else fill_payload(u + 8, plen, NULL);
    emit_ip(ts, s, d, 17, u, 8 + plen, 6);
}

static void icmp_echo(double ts, ip_t s, ip_t d, int reply, uint16_t id, uint16_t sq)
{
    uint8_t *c = l4buf;
    int v6 = s.v6;
    c[0] = v6 ? (reply ? 129 : 128) : (reply ? 0 : 8);
    c[1] = 0;
    w16(c + 2, 0);
    w16(c + 4, id);
    w16(c + 6, sq);
    fill_payload(c + 8, 56, "abcdefghijklmnopqrstuvwabcdefghi");
    if (!v6) {
        w16(c + 2, csum_fin(csum_add(0, c, 64)));
        emit_ip(ts, s, d, 1, c, 64, -1);
    } else {
        emit_ip(ts, s, d, 58, c, 64, 2);
    }
}

static void arp_pkt(double ts, int who, int asker)
{
    uint8_t *p = pktbuf;
    memset(p, 0xFF, 6);
    uint8_t mac[6] = {0x00, 0x1b, 0x21, 0x3a, 0x4f, (uint8_t)asker};
    memcpy(p + 6, mac, 6);
    w16(p + 12, 0x0806);
    uint8_t *a = p + 14;
    w16(a, 1); w16(a + 2, 0x0800); a[4] = 6; a[5] = 4; w16(a + 6, 1);
    memcpy(a + 8, mac, 6);
    a[14] = 192; a[15] = 168; a[16] = 1; a[17] = (uint8_t)asker;
    memset(a + 18, 0, 6);
    a[24] = 192; a[25] = 168; a[26] = 1; a[27] = (uint8_t)who;
    memset(p + 42, 0, 18);
    store(ts, 0, p, 60);
}

/* ------------------------------------------------------------------ TCP sessions */

typedef struct {
    ip_t     c, s;
    uint16_t cp, sp;
    uint32_t cseq, sseq;
    double   rtt;
} sess_t;

static sess_t sess(ip_t c, uint16_t cp, ip_t s, uint16_t sp, double rtt)
{
    sess_t x = {c, s, cp, sp, rnd(), rnd(), rtt};
    return x;
}

/* returns time after handshake */
static double handshake(sess_t *x, double t)
{
    tcp_pkt(t, x->c, x->cp, x->s, x->sp, x->cseq, 0, 0x02, 64240, 0, NULL);
    x->cseq++;
    tcp_pkt(t + x->rtt / 2, x->s, x->sp, x->c, x->cp, x->sseq, x->cseq, 0x12, 65160, 0, NULL);
    x->sseq++;
    tcp_pkt(t + x->rtt, x->c, x->cp, x->s, x->sp, x->cseq, x->sseq, 0x10, 502, 0, NULL);
    return t + x->rtt;
}

/* send n bytes in MSS segments; dir 0 = client->server. loss = probability of retransmission */
static double transfer(sess_t *x, double t, int dir, uint32_t n, double rate_bps, double loss, const char *text,
                       int zero_win_events)
{
    const uint32_t mss = 1448;
    double dt = rate_bps > 0 ? mss * 8.0 / rate_bps : 0.0005;
    uint32_t segs = 0;
    while (n > 0) {
        uint32_t l = n < mss ? n : mss;
        ip_t s = dir ? x->s : x->c, d = dir ? x->c : x->s;
        uint16_t sp = dir ? x->sp : x->cp, dp = dir ? x->cp : x->sp;
        uint32_t *seq = dir ? &x->sseq : &x->cseq;
        uint32_t ack = dir ? x->cseq : x->sseq;
        tcp_pkt(t, s, sp, d, dp, *seq, ack, 0x18, 502, l, text);
        if (loss > 0 && rndf() < loss) {
            /* segment "lost" downstream: retransmitted after RTO */
            tcp_pkt(t + x->rtt * 3, s, sp, d, dp, *seq, ack, 0x18, 502, l, text);
        }
        *seq += l;
        n -= l;
        segs++;
        if (segs % 2 == 0 || n == 0) {
            uint16_t win = 502;
            if (zero_win_events > 0 && segs % 40 == 0) { win = 0; zero_win_events--; }
            tcp_pkt(t + x->rtt / 2, d, dp, s, sp, dir ? x->cseq : x->sseq, *seq, 0x10, win, 0, NULL);
            if (win == 0) {
                tcp_pkt(t + x->rtt / 2 + 0.2, d, dp, s, sp, dir ? x->cseq : x->sseq, *seq, 0x10, 502, 0, NULL);
                t += 0.2;
            }
        }
        t += dt;
    }
    return t;
}

static double close_fin(sess_t *x, double t)
{
    tcp_pkt(t, x->c, x->cp, x->s, x->sp, x->cseq, x->sseq, 0x11, 502, 0, NULL);
    x->cseq++;
    tcp_pkt(t + x->rtt / 2, x->s, x->sp, x->c, x->cp, x->sseq, x->cseq, 0x11, 502, 0, NULL);
    x->sseq++;
    tcp_pkt(t + x->rtt, x->c, x->cp, x->s, x->sp, x->cseq, x->sseq, 0x10, 502, 0, NULL);
    return t + x->rtt;
}

/* request/response session */
static void web_session(ip_t c, ip_t s, uint16_t port, double t, double rtt, uint32_t req, uint32_t resp,
                        double rate, const char *req_text, double loss)
{
    sess_t x = sess(c, (uint16_t)rndr(49152, 65000), s, port, rtt);
    t = handshake(&x, t);
    t = transfer(&x, t + 0.001, 0, req, 0, 0, req_text, 0);
    t = transfer(&x, t + rtt, 1, resp, rate, loss, NULL, 0);
    close_fin(&x, t + 0.05 + rndf() * 0.5);
}

/* ------------------------------------------------------------------ DNS */

static uint32_t dns_msg(uint8_t *b, uint16_t id, const char *name, uint16_t qtype, int response, int rcode,
                        const uint8_t *answer_ip)
{
    w16(b, id);
    w16(b + 2, response ? (uint16_t)(0x8180 | rcode) : 0x0100);
    w16(b + 4, 1);
    w16(b + 6, response && rcode == 0 && answer_ip ? 1 : 0);
    w16(b + 8, 0);
    w16(b + 10, 0);
    uint32_t o = 12;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        b[o++] = (uint8_t)l;
        memcpy(b + o, p, l);
        o += (uint32_t)l;
        p += l;
        if (*p == '.') p++;
    }
    b[o++] = 0;
    w16(b + o, qtype); w16(b + o + 2, 1); o += 4;
    if (response && rcode == 0 && answer_ip) {
        w16(b + o, 0xC00C); w16(b + o + 2, qtype); w16(b + o + 4, 1);
        w32(b + o + 6, 300);
        if (qtype == 28) { w16(b + o + 10, 16); memcpy(b + o + 12, answer_ip, 16); o += 28; }
        else { w16(b + o + 10, 4); memcpy(b + o + 12, answer_ip, 4); o += 16; }
    }
    return o;
}

static void dns_lookup(double t, ip_t c, ip_t srv, const char *name, uint16_t qtype, int rcode, double rtt)
{
    uint8_t b[600];
    uint16_t id = (uint16_t)rnd();
    uint16_t sp = (uint16_t)rndr(30000, 60000);
    uint32_t n = dns_msg(b, id, name, qtype, 0, 0, NULL);
    udp_pkt(t, c, sp, srv, 53, b, n);
    uint8_t ans[16] = {93, 184, (uint8_t)rndr(1, 254), (uint8_t)rndr(1, 254)};
    if (qtype == 28) { ans[0] = 0x26; ans[1] = 0x06; ans[15] = 1; }
    n = dns_msg(b, id, name, qtype, 1, rcode, ans);
    udp_pkt(t + rtt, srv, 53, c, sp, b, n);
}

static void random_label(char *out, int n, const char *alphabet)
{
    size_t al = strlen(alphabet);
    for (int i = 0; i < n; i++) out[i] = alphabet[rnd() % al];
    out[n] = 0;
}

/* ------------------------------------------------------------------ scenarios */

static const char *HTTP_GET = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n";
static const char *SITES[] = {"www.google.com", "github.com", "api.github.com", "cdn.jsdelivr.net",
                              "www.wikipedia.org", "outlook.office365.com", "teams.microsoft.com",
                              "fonts.googleapis.com", "update.ubuntu.com", "pypi.org", "stackoverflow.com"};

static void background_office(double t0, double span, int clients, int sessions_per_client, double loss)
{
    ip_t gw = ip4(192, 168, 1, 1);
    ip_t servers[] = {ip4(142, 250, 74, 14), ip4(140, 82, 121, 4), ip4(151, 101, 1, 69), ip4(104, 16, 132, 229),
                      ip4(52, 97, 146, 2), ip4(13, 107, 42, 14), ip4(185, 125, 190, 36)};
    int nsrv = (int)(sizeof servers / sizeof servers[0]);
    for (int c = 0; c < clients; c++) {
        ip_t cl = ip4(192, 168, 1, 10 + c);
        for (int k = 0; k < sessions_per_client; k++) {
            double t = t0 + rndf() * span * 0.9;
            const char *site = SITES[rnd() % (sizeof SITES / sizeof SITES[0])];
            dns_lookup(t, cl, gw, site, 1, 0, 0.004 + rndf() * 0.02);
            ip_t s = servers[rnd() % (uint32_t)nsrv];
            double rtt = 0.008 + rndf() * 0.04;
            uint32_t resp = rndr(2000, 400000);
            web_session(cl, s, 443, t + 0.03, rtt, rndr(300, 1500), resp, 20e6 + rndf() * 60e6, NULL, loss);
        }
        /* QUIC */
        double t = t0 + rndf() * span * 0.8;
        uint16_t sp = (uint16_t)rndr(50000, 60000);
        for (int i = 0; i < 60; i++) {
            udp_pkt(t, cl, sp, ip4(142, 250, 74, 14), 443, NULL, rndr(30, 120));
            udp_pkt(t + 0.012, ip4(142, 250, 74, 14), 443, cl, sp, NULL, 1200 + rndr(0, 50));
            t += 0.02 + rndf() * 0.05;
        }
    }
    /* plain HTTP */
    for (int i = 0; i < 4; i++)
        web_session(ip4(192, 168, 1, 10 + i), ip4(93, 184, 216, 34), 80, t0 + rndf() * span * 0.9, 0.03, 90, 4000,
                    10e6, HTTP_GET, 0);
    /* NTP */
    for (int i = 0; i < 3; i++) {
        uint8_t ntp[48] = {0x23};
        double t = t0 + rndf() * span;
        udp_pkt(t, ip4(192, 168, 1, 10 + i), 123, ip4(162, 159, 200, 1), 123, ntp, 48);
        ntp[0] = 0x24;
        udp_pkt(t + 0.015, ip4(162, 159, 200, 1), 123, ip4(192, 168, 1, 10 + i), 123, ntp, 48);
    }
    /* ICMP + ARP */
    for (int i = 0; i < 10; i++) {
        double t = t0 + i * span / 10;
        icmp_echo(t, ip4(192, 168, 1, 11), ip4(8, 8, 8, 8), 0, 77, (uint16_t)i);
        icmp_echo(t + 0.012, ip4(8, 8, 8, 8), ip4(192, 168, 1, 11), 1, 77, (uint16_t)i);
        arp_pkt(t + 0.3, 1, 10 + i);
    }
}

static void gen_normal(const char *dir)
{
    char path[1024];
    double t0 = 1700000000.0; /* 2023-11-14 22:13:20 UTC */
    g_iface = 0;
    g_vlan = 0;
    background_office(t0, 60, 14, 8, 0.0);

    /* long interactive SSH session */
    sess_t x = sess(ip4(192, 168, 1, 12), 51515, ip4(140, 82, 121, 4), 22, 0.025);
    double t = handshake(&x, t0 + 0.5);
    while (t < t0 + 58) {
        t = transfer(&x, t + 0.2 + rndf() * 1.5, 0, rndr(36, 120), 0, 0, NULL, 0);
        t = transfer(&x, t + 0.03, 1, rndr(36, 900), 0, 0, NULL, 0);
    }
    close_fin(&x, t + 0.1);

    /* one slightly lossy download */
    web_session(ip4(192, 168, 1, 20), ip4(185, 125, 190, 36), 443, t0 + 20, 0.035, 500, 1500000, 30e6, NULL, 0.02);

    snprintf(path, sizeof path, "%s/normal.pcap", dir);
    write_pcap(path, 1, 65535);
}

static void gen_attacks(const char *dir)
{
    char path[1024];
    double t0 = 1700100000.0;
    g_iface = 0;
    g_vlan = 0;
    background_office(t0, 600, 6, 10, 0.0);

    ip_t att = ip4(10, 0, 0, 66);
    ip_t victim = ip4(10, 0, 0, 5);

    /* 1) SYN port scan 1-1024 (nmap -sS) */
    double t = t0 + 10;
    for (int port = 1; port <= 1024; port++) {
        uint32_t seq = rnd();
        uint16_t sp = 40000 + (uint16_t)(rnd() % 4);
        tcp_pkt(t, att, sp, victim, (uint16_t)port, seq, 0, 0x02, 1024, 0, NULL);
        if (port == 22 || port == 80 || port == 443 || port == 3306) {
            uint32_t sseq = rnd();
            tcp_pkt(t + 0.0004, victim, (uint16_t)port, att, sp, sseq, seq + 1, 0x12, 65160, 0, NULL);
            tcp_pkt(t + 0.0008, att, sp, victim, (uint16_t)port, seq + 1, 0, 0x04, 0, 0, NULL);
        } else {
            tcp_pkt(t + 0.0003, victim, (uint16_t)port, att, sp, 0, seq + 1, 0x14, 0, 0, NULL);
        }
        t += 0.002;
    }

    /* 2) XMAS scan + NULL scan */
    t = t0 + 15;
    ip_t v2 = ip4(10, 0, 0, 6);
    for (int port = 1; port <= 150; port++) {
        uint32_t seq = rnd();
        tcp_pkt(t, att, 45555, v2, (uint16_t)port, seq, 0, 0x29, 1024, 0, NULL);
        if (port != 22 && port != 80) tcp_pkt(t + 0.0003, v2, (uint16_t)port, att, 45555, 0, seq, 0x14, 0, 0, NULL);
        t += 0.003;
    }
    for (int port = 20; port < 30; port++) tcp_pkt(t + port * 0.01, att, 45556, ip4(10, 0, 0, 7), (uint16_t)port, rnd(), 0, 0x00, 1024, 0, NULL);

    /* 3) horizontal sweep on SMB (445) */
    t = t0 + 20;
    for (int h = 1; h <= 60; h++) {
        ip_t d = ip4(10, 0, 1, h);
        uint32_t seq = rnd();
        uint16_t sp = (uint16_t)rndr(40000, 60000);
        tcp_pkt(t, att, sp, d, 445, seq, 0, 0x02, 1024, 0, NULL);
        if (h % 12 == 0) {
            tcp_pkt(t + 0.0005, d, 445, att, sp, rnd(), seq + 1, 0x12, 65160, 0, NULL);
            tcp_pkt(t + 0.001, att, sp, d, 445, seq + 1, 0, 0x04, 0, 0, NULL);
        }
        t += 0.01;
    }

    /* 4) SYN flood from spoofed sources on 10.0.0.80:80 */
    t = t0 + 30;
    ip_t web = ip4(10, 0, 0, 80);
    for (int i = 0; i < 3000; i++) {
        ip_t s = ip4((int)rndr(11, 223), (int)rndr(0, 255), (int)rndr(0, 255), (int)rndr(1, 254));
        uint16_t sp = (uint16_t)rndr(1024, 65535);
        uint32_t seq = rnd();
        tcp_pkt(t, s, sp, web, 80, seq, 0, 0x02, 512, 0, NULL);
        if (i < 800) tcp_pkt(t + 0.0002, web, 80, s, sp, rnd(), seq + 1, 0x12, 65160, 0, NULL);
        t += 0.0013;
    }

    /* 5) UDP flood on 10.0.0.90:9999 */
    t = t0 + 40;
    ip_t udpv = ip4(10, 0, 0, 90);
    for (int i = 0; i < 9000; i++) {
        udp_pkt(t, ip4(198, 51, 100, 23), (uint16_t)rndr(1024, 65535), udpv, 9999, NULL, 512);
        t += 0.0006;
    }

    /* 6) DNS tunnelling */
    t = t0 + 60;
    ip_t dnsrv = ip4(10, 0, 0, 1);
    for (int i = 0; i < 120; i++) {
        char lab[64], name[200];
        random_label(lab, 52, "abcdefghijklmnopqrstuvwxyz234567");
        snprintf(name, sizeof name, "%s.%d.t.evil-tunnel.com", lab, i);
        dns_lookup(t, ip4(10, 0, 0, 23), dnsrv, name, 16, 0, 0.03);
        t += 0.4 + rndf() * 0.3;
    }

    /* 7) DGA - many NXDOMAIN */
    t = t0 + 90;
    for (int i = 0; i < 70; i++) {
        char lab[32], name[64];
        random_label(lab, 14, "abcdefghijklmnopqrstuvwxyz");
        snprintf(name, sizeof name, "%s.net", lab);
        dns_lookup(t, ip4(10, 0, 0, 31), dnsrv, name, 1, 3, 0.02);
        t += 0.8 + rndf();
    }

    /* 8) beaconing to C2 every 30 s */
    t = t0 + 5;
    for (int i = 0; i < 18; i++) {
        double rtt = 0.06;
        sess_t x = sess(ip4(10, 0, 0, 44), (uint16_t)rndr(49152, 65000), ip4(203, 0, 113, 50), 8443, rtt);
        double tt = handshake(&x, t);
        tt = transfer(&x, tt + 0.001, 0, 220, 0, 0, NULL, 0);
        tt = transfer(&x, tt + rtt, 1, 90, 0, 0, NULL, 0);
        close_fin(&x, tt + 0.01);
        t += 30.0 + (rndf() - 0.5) * 1.0;
    }

    /* 9) telnet session (cleartext) */
    {
        sess_t x = sess(ip4(10, 0, 0, 12), 50123, ip4(10, 0, 0, 200), 23, 0.002);
        double tt = handshake(&x, t0 + 100);
        for (int i = 0; i < 30; i++) {
            tt = transfer(&x, tt + 0.3, 0, 8, 0, 0, "admin\r\npassword123\r\n", 0);
            tt = transfer(&x, tt + 0.01, 1, 60, 0, 0, "Login: Password: Welcome to router\r\n# ", 0);
        }
        close_fin(&x, tt + 0.2);
    }

    /* 10) reverse shell on 4444 */
    {
        sess_t x = sess(ip4(10, 0, 0, 77), 49999, ip4(185, 220, 101, 4), 4444, 0.08);
        double tt = handshake(&x, t0 + 130);
        for (int i = 0; i < 25; i++) {
            tt = transfer(&x, tt + 1.0 + rndf(), 1, rndr(10, 40), 0, 0, "whoami\nid\ncat /etc/passwd\n", 0);
            tt = transfer(&x, tt + 0.05, 0, rndr(50, 1400), 0, 0, "root:x:0:0:root:/root:/bin/bash\n", 0);
        }
        close_fin(&x, tt + 0.5);
    }

    /* 11) large outbound transfer (exfiltration) */
    {
        sess_t x = sess(ip4(10, 0, 0, 15), 55001, ip4(45, 83, 64, 10), 443, 0.04);
        double tt = handshake(&x, t0 + 200);
        tt = transfer(&x, tt + 0.01, 0, 11u * 1000u * 1000u, 40e6, 0, NULL, 0);
        tt = transfer(&x, tt + 0.04, 1, 2000, 0, 0, NULL, 0);
        close_fin(&x, tt + 0.1);
    }

    /* 12) lossy download with zero-window episodes */
    {
        sess_t x = sess(ip4(10, 0, 0, 16), 56002, ip4(10, 0, 0, 250), 8080, 0.01);
        double tt = handshake(&x, t0 + 260);
        tt = transfer(&x, tt + 0.01, 0, 120, 0, 0, HTTP_GET, 0);
        tt = transfer(&x, tt + 0.01, 1, 2500000, 50e6, 0.12, NULL, 6);
        close_fin(&x, tt + 0.1);
    }

    /* 13) a couple of malformed IPv4 headers (IHL < 5) */
    for (int i = 0; i < 3; i++) {
        uint8_t *p = pktbuf;
        memset(p, 0, 60);
        w16(p + 12, 0x0800);
        p[14] = 0x43;
        w16(p + 16, 40);
        p[22] = 64; p[23] = 6;
        p[26] = 10; p[29] = 66; p[30] = 10; p[33] = 5;
        store(t0 + 300 + i, 0, p, 60);
    }

    snprintf(path, sizeof path, "%s/attacks.pcap", dir);
    write_pcap(path, 1, 65535);
}

static void gen_mixed(const char *dir)
{
    char path[1024];
    double t0 = 1700200000.123456789;

    /* interface 0: Ethernet with VLAN 42, IPv6 + IPv4 */
    g_iface = 0;
    g_vlan = 42;
    ip_t c6 = ip6(0x2001, 0xdb8, 0, 0x10), r6 = ip6(0x2001, 0xdb8, 0, 0x1), s6 = ip6(0x2606, 0x4700, 0, 0x1111);
    for (int i = 0; i < 12; i++) {
        double t = t0 + i * 2.3 + rndf() * 1.7;
        dns_lookup(t, c6, r6, SITES[i % 11], 28, 0, 0.006);
        web_session(c6, s6, 443, t + 0.02, 0.018, 700, rndr(5000, 120000), 50e6, NULL, 0);
    }
    for (int i = 0; i < 8; i++) {
        icmp_echo(t0 + i, c6, s6, 0, 9, (uint16_t)i);
        icmp_echo(t0 + i + 0.018, s6, c6, 1, 9, (uint16_t)i);
    }
    g_vlan = 0;
    for (int i = 0; i < 6; i++)
        web_session(ip4(172, 16, 5, 20 + i), ip4(172, 16, 0, 10), 3306, t0 + 3 + i * 3, 0.001, 200, 30000, 200e6, NULL, 0);

    /* interface 1: raw IP (e.g. tunnel interface) */
    g_iface = 1;
    g_ttl = 128;
    for (int i = 0; i < 10; i++) {
        uint8_t b[64];
        for (int k = 0; k < 64; k++) b[k] = (uint8_t)k;
        udp_pkt(t0 + i * 1.5, ip4(100, 64, 0, 2), 51820, ip4(100, 64, 0, 1), 51820, b, 64);
        udp_pkt(t0 + i * 1.5 + 0.02, ip4(100, 64, 0, 1), 51820, ip4(100, 64, 0, 2), 51820, b, 32);
    }
    web_session(ip4(100, 64, 0, 2), ip4(100, 64, 0, 9), 22, t0 + 4, 0.03, 2000, 50000, 5e6, NULL, 0);
    g_iface = 0;
    g_ttl = 64;

    snprintf(path, sizeof path, "%s/mixed.pcapng", dir);
    write_pcapng(path, 128);
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : ".";
    printf("Generowanie przykładowych plików w %s/\n", dir);
    gen_normal(dir);
    gen_attacks(dir);
    gen_mixed(dir);
    free(recs);
    return 0;
}
