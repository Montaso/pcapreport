#include "analyzer.h"
#include "pcap_reader.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

const char *const PROTO_NAMES[P_COUNT] = {"TCP", "UDP", "ICMP", "Inne IP", "Nie-IP"};
const char *const SIZE_BIN_LABELS[SIZE_BINS] = {"<=64", "65-127", "128-255", "256-511",
                                                "512-1023", "1024-1518", ">1518"};
const char *const TCS_NAMES[TCS_COUNT] = {
    "Zamknięte poprawnie (FIN)", "Otwarte (bez zamknięcia)", "Zerwane (RST)",
    "Odrzucone (SYN -> RST)", "Bez odpowiedzi (SYN)", "Półotwarte (brak ACK)",
    "Przechwycone w trakcie"};
const char *const FLAG_NAMES[F_COUNT] = {"SYN", "SYN+ACK", "ACK", "PSH", "FIN", "RST", "URG", "ECE/CWR"};
const char *const BADFLAG_NAMES[BF_COUNT] = {"NULL (brak flag)", "XMAS (FIN+PSH+URG)", "SYN+FIN", "SYN+RST"};

static int size_bin(uint32_t len)
{
    if (len <= 64) return 0;
    if (len <= 127) return 1;
    if (len <= 255) return 2;
    if (len <= 511) return 3;
    if (len <= 1023) return 4;
    if (len <= 1518) return 5;
    return 6;
}

const char *service_name(uint8_t proto, uint16_t port)
{
    static const struct { uint8_t proto; uint16_t port; const char *name; } T[] = {
        {6, 20, "FTP-data"}, {6, 21, "FTP"}, {6, 22, "SSH"}, {6, 23, "Telnet"}, {6, 25, "SMTP"},
        {6, 53, "DNS"}, {17, 53, "DNS"}, {17, 67, "DHCP"}, {17, 68, "DHCP"}, {17, 69, "TFTP"},
        {6, 80, "HTTP"}, {6, 88, "Kerberos"}, {17, 88, "Kerberos"}, {6, 110, "POP3"},
        {17, 123, "NTP"}, {6, 135, "MS-RPC"}, {17, 137, "NetBIOS-NS"}, {17, 138, "NetBIOS-DGM"},
        {6, 139, "NetBIOS-SSN"}, {6, 143, "IMAP"}, {17, 161, "SNMP"}, {17, 162, "SNMP-trap"},
        {6, 179, "BGP"}, {6, 389, "LDAP"}, {6, 443, "HTTPS"}, {17, 443, "QUIC"}, {6, 445, "SMB"},
        {17, 500, "IKE"}, {17, 514, "Syslog"}, {6, 587, "SMTP-sub"}, {6, 636, "LDAPS"},
        {6, 853, "DNS-over-TLS"}, {6, 993, "IMAPS"}, {6, 995, "POP3S"}, {17, 1194, "OpenVPN"},
        {6, 1433, "MSSQL"}, {6, 1521, "Oracle"}, {17, 1900, "SSDP"}, {6, 2049, "NFS"},
        {6, 3306, "MySQL"}, {6, 3389, "RDP"}, {17, 3478, "STUN"}, {6, 4444, "Metasploit"},
        {17, 4500, "IPsec-NAT"}, {6, 5060, "SIP"}, {17, 5060, "SIP"}, {17, 5353, "mDNS"},
        {17, 5355, "LLMNR"}, {6, 5432, "PostgreSQL"}, {6, 5900, "VNC"}, {6, 6379, "Redis"},
        {6, 6667, "IRC"}, {6, 8080, "HTTP-alt"}, {6, 8443, "HTTPS-alt"}, {6, 9200, "Elastic"},
        {6, 27017, "MongoDB"}, {6, 31337, "BackOrifice"}, {17, 51820, "WireGuard"},
    };
    for (size_t i = 0; i < ARRAY_LEN(T); i++)
        if (T[i].proto == proto && T[i].port == port) return T[i].name;
    return NULL;
}

/* ------------------------------------------------------------------ prescan */

uint64_t analysis_prescan(char **paths, int n, double *t0, double *t1)
{
    uint64_t cnt = 0;
    double lo = 0, hi = 0;
    int have = 0;
    for (int i = 0; i < n; i++) {
        pcap_reader_t r;
        if (pr_open(&r, paths[i]) != 0) { pr_close(&r); continue; }
        raw_packet_t p;
        while (pr_next(&r, &p) == 1) {
            cnt++;
            if (p.ts <= 0) continue;
            if (!have) { lo = hi = p.ts; have = 1; }
            if (p.ts < lo) lo = p.ts;
            if (p.ts > hi) hi = p.ts;
        }
        pr_close(&r);
    }
    *t0 = lo;
    *t1 = hi;
    return cnt;
}

static double choose_bucket(double span)
{
    static const double steps[] = {0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5,
                                   10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 21600,
                                   43200, 86400};
    double want = span / 300.0;
    for (size_t i = 0; i < ARRAY_LEN(steps); i++)
        if (steps[i] >= want) return steps[i];
    return ceil(want / 86400.0) * 86400.0;
}

void analysis_init(analysis_t *an, double t0, double t1, const analysis_opts_t *o)
{
    memset(an, 0, sizeof *an);
    hmap_init(&an->flowmap);
    hmap_init(&an->hostmap);
    hmap_init(&an->dnsmap);
    an->min_len = UINT32_MAX;
    an->first_ts = 0;
    an->last_ts = 0;

    double span = t1 - t0;
    if (span < 0) span = 0;
    an->tl_t0 = t0;
    an->tl_bucket = o->bucket > 0 ? o->bucket : choose_bucket(span);
    double nb = floor(span / an->tl_bucket) + 1;
    if (nb > 200000) { an->tl_bucket = choose_bucket(span); nb = floor(span / an->tl_bucket) + 1; }
    an->tl_n = (int)nb;
    for (int s = 0; s < TL_COUNT; s++) {
        an->tl_bytes[s] = xcalloc((size_t)an->tl_n, sizeof(double));
        an->tl_pkts[s] = xcalloc((size_t)an->tl_n, sizeof(double));
    }
}

/* ------------------------------------------------------------------ hosts */

static host_t *host_get(analysis_t *an, const addr_t *a)
{
    uint8_t key[17];
    key[0] = a->ver;
    memcpy(key + 1, a->a, 16);
    int idx = hmap_get(&an->hostmap, key, sizeof key);
    if (idx >= 0) return &an->hosts[idx];
    VEC_RESERVE(an->hosts, an->chosts, an->nhosts + 1);
    host_t *h = &an->hosts[an->nhosts];
    memset(h, 0, sizeof *h);
    h->a = *a;
    hmap_put(&an->hostmap, key, sizeof key, (int)an->nhosts);
    an->nhosts++;
    return h;
}

host_t *analysis_host(analysis_t *an, const addr_t *a)
{
    uint8_t key[17];
    key[0] = a->ver;
    memcpy(key + 1, a->a, 16);
    int idx = hmap_get(&an->hostmap, key, sizeof key);
    return idx >= 0 ? &an->hosts[idx] : NULL;
}

/* ------------------------------------------------------------------ flows */

static size_t flow_key(uint8_t *k, uint8_t proto, const addr_t *a, uint16_t pa, const addr_t *b,
                       uint16_t pb)
{
    int c = addr_cmp(a, b);
    if (c > 0 || (c == 0 && pa > pb)) {
        const addr_t *t = a; a = b; b = t;
        uint16_t tp = pa; pa = pb; pb = tp;
    }
    k[0] = proto;
    k[1] = a->ver;
    memcpy(k + 2, a->a, 16);
    memcpy(k + 18, b->a, 16);
    k[34] = (uint8_t)(pa >> 8); k[35] = (uint8_t)pa;
    k[36] = (uint8_t)(pb >> 8); k[37] = (uint8_t)pb;
    return 38;
}

static int client_is_src(const pkt_t *p)
{
    if (p->proto == IPPROTO_TCP_ && (p->tcp_flags & TCP_SYN))
        return !(p->tcp_flags & TCP_ACK);
    /* the well-known (low) port is the service side */
    if (p->dport < 1024 && p->sport >= 1024) return 1;
    if (p->sport < 1024 && p->dport >= 1024) return 0;
    return 1; /* first sender initiates */
}

static flow_t *flow_get(analysis_t *an, const pkt_t *p, int *dir, const analysis_opts_t *o)
{
    uint8_t key[38];
    size_t kl = flow_key(key, p->proto, &p->src, p->sport, &p->dst, p->dport);
    int idx = hmap_get(&an->flowmap, key, kl);
    if (idx >= 0) {
        flow_t *f = &an->flows[idx];
        int fresh = 0;
        if (p->ts - f->last > o->flow_timeout) fresh = 1;
        if (p->proto == IPPROTO_TCP_ && (p->tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN &&
            ((f->fin[0] && f->fin[1]) || f->rst[0] || f->rst[1]) && f->hs_done)
            fresh = 1; /* port reuse after a completed connection */
        if (!fresh) {
            *dir = (addr_cmp(&p->src, &f->cli) == 0 && p->sport == f->cport) ? 0 : 1;
            return f;
        }
    }

    VEC_RESERVE(an->flows, an->cflows, an->nflows + 1);
    flow_t *f = &an->flows[an->nflows];
    memset(f, 0, sizeof *f);
    f->proto = p->proto;
    if (client_is_src(p)) {
        f->cli = p->src; f->cport = p->sport;
        f->srv = p->dst; f->sport = p->dport;
    } else {
        f->cli = p->dst; f->cport = p->dport;
        f->srv = p->src; f->sport = p->sport;
    }
    f->first = f->last = p->ts;
    f->rtt = -1;
    hmap_put(&an->flowmap, key, kl, (int)an->nflows);
    an->nflows++;
    if (p->proto == IPPROTO_TCP_) an->tcp_flows++;
    else an->udp_flows++;

    host_get(an, &f->cli)->flows_cli++;
    /* host_get may realloc hosts only, flows array is stable here */
    host_get(an, &f->srv)->flows_srv++;

    *dir = (addr_cmp(&p->src, &f->cli) == 0 && p->sport == f->cport) ? 0 : 1;
    return f;
}

static void tcp_update(analysis_t *an, flow_t *f, int d, const pkt_t *p)
{
    uint8_t fl = p->tcp_flags;
    f->flags_seen[d] |= fl;

    if ((fl & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
        f->syn_seen = 1;
        f->syn_count++;
        if (!f->synack_seen) f->syn_ts = p->ts;   /* latest SYN before SYN/ACK */
    }
    if ((fl & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) && !f->synack_seen) {
        f->synack_seen = 1;
        f->synack_ts = p->ts;
        if (f->syn_seen && p->ts >= f->syn_ts) f->rtt = p->ts - f->syn_ts;
    }
    if (!(fl & TCP_SYN) && (fl & TCP_ACK) && d == 0 && f->synack_seen) f->hs_done = 1;
    if (fl & TCP_FIN) f->fin[d] = 1;
    if (fl & TCP_RST) f->rst[d] = 1;

    /* invalid flag combinations */
    int bad = -1;
    if ((fl & 0x3F) == 0) bad = BF_NULL;
    else if ((fl & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG) && !(fl & TCP_SYN)) bad = BF_XMAS;
    else if ((fl & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN)) bad = BF_SYNFIN;
    else if ((fl & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST)) bad = BF_SYNRST;
    if (bad >= 0) {
        an->bad_flags[bad]++;
        f->bad_flags |= (uint8_t)(1u << bad);
        host_get(an, &p->src)->bad_flags_tx++;
    }

    if ((fl & TCP_ACK) && !(fl & (TCP_RST | TCP_SYN | TCP_FIN)) && p->window == 0) {
        f->zero_win[d]++;
        an->tcp_zero_win++;
    }

    /* sequence analysis: retransmissions & gaps */
    if (fl & TCP_RST) return;
    uint32_t seglen = p->payload_len + ((fl & TCP_SYN) ? 1u : 0u) + ((fl & TCP_FIN) ? 1u : 0u);
    if (p->payload_len > 0) { f->data_segs[d]++; an->tcp_data_segs++; }
    if (!f->seq_valid[d]) {
        f->seq_valid[d] = 1;
        f->next_seq[d] = p->seq + seglen;
        return;
    }
    if (seglen == 0) return;
    int32_t diff = (int32_t)(p->seq - f->next_seq[d]);
    if (diff < 0) {
        int keepalive = p->payload_len <= 1 && diff == -1 && !(fl & (TCP_SYN | TCP_FIN));
        if (!keepalive) { f->retrans[d]++; an->tcp_retrans++; }
        uint32_t end = p->seq + seglen;
        if ((int32_t)(end - f->next_seq[d]) > 0) f->next_seq[d] = end;
    } else {
        if (diff > 0) { f->ooo[d]++; an->tcp_ooo++; }
        f->next_seq[d] = p->seq + seglen;
    }
}

/* ------------------------------------------------------------------ DNS */

static double label_entropy(const char *s, size_t n)
{
    if (!n) return 0;
    int cnt[256] = {0};
    for (size_t i = 0; i < n; i++) cnt[(uint8_t)s[i]]++;
    double h = 0;
    for (int i = 0; i < 256; i++) {
        if (!cnt[i]) continue;
        double q = (double)cnt[i] / (double)n;
        h -= q * log2(q);
    }
    return h;
}

static void dns_parse(analysis_t *an, const pkt_t *p)
{
    const uint8_t *d = p->payload;
    uint32_t n = p->payload_cap;
    if (!d || n < 12) { an->dns_malformed++; return; }
    uint16_t flags = rd16be(d + 2);
    uint16_t qd = rd16be(d + 4);
    int qr = flags >> 15;
    int rcode = flags & 0x0F;
    if (qr) {
        an->dns_responses++;
        if (rcode == 3) an->dns_nxdomain++;
        else if (rcode == 2) an->dns_servfail++;
        else if (rcode != 0) an->dns_other_err++;
    } else {
        an->dns_queries++;
    }
    if (qd < 1) return;

    /* first question name */
    char name[256];
    size_t nl = 0, longest = 0, lstart = 0, best_start = 0;
    uint32_t o = 12;
    int ok = 0;
    while (o < n) {
        uint8_t l = d[o];
        if (l == 0) { ok = 1; break; }
        if (l & 0xC0) break;                 /* compression in question: unusual */
        if (o + 1 + l > n || nl + l + 2 >= sizeof name) break;
        if (nl) name[nl++] = '.';
        lstart = nl;
        for (uint8_t i = 0; i < l; i++) {
            char c = (char)d[o + 1 + i];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            if ((unsigned char)c < 0x21 || (unsigned char)c > 0x7E) c = '?';
            name[nl++] = c;
        }
        if (l > longest) { longest = l; best_start = lstart; }
        o += 1u + l;
    }
    if (!ok) { an->dns_malformed++; return; }
    if (nl == 0) { strcpy(name, "<root>"); nl = 6; }
    name[nl] = 0;

    int idx = hmap_get(&an->dnsmap, name, nl);
    if (idx < 0) {
        VEC_RESERVE(an->dns_names, an->cdns, an->ndns + 1);
        dns_name_t *e = &an->dns_names[an->ndns];
        memset(e, 0, sizeof *e);
        e->name = xstrdup(name);
        e->first_client = qr ? p->dst : p->src;
        e->longest_label = (uint16_t)longest;
        e->entropy = label_entropy(name + best_start, longest);
        hmap_put(&an->dnsmap, name, nl, (int)an->ndns);
        idx = (int)an->ndns++;
    }
    dns_name_t *e = &an->dns_names[idx];
    if (!qr) e->queries++;
    else if (rcode == 3) e->nxdomain++;
}

/* ------------------------------------------------------------------ per packet */

static void process_packet(analysis_t *an, const pkt_t *p, const analysis_opts_t *o)
{
    an->packets++;
    an->bytes += p->wire_len;
    an->cap_bytes += p->cap_len;
    if (p->wire_len < an->min_len) an->min_len = p->wire_len;
    if (p->wire_len > an->max_len) an->max_len = p->wire_len;

    if (p->ts > 0) {
        if (an->first_ts == 0 || p->ts < an->first_ts) an->first_ts = p->ts;
        if (p->ts > an->last_ts) an->last_ts = p->ts;
    } else {
        an->zero_ts++;
    }
    if (p->unsupported_link) an->unsupported_link++;
    if (p->truncated) an->truncated++;
    if (p->malformed) an->malformed++;
    if (p->ethertype == 0x0806) an->arp++;

    int pc;
    if (p->l3 == L3_NONE) pc = P_NON_IP;
    else if (p->proto == IPPROTO_TCP_) pc = P_TCP;
    else if (p->proto == IPPROTO_UDP_) pc = P_UDP;
    else if (p->proto == IPPROTO_ICMP_ || p->proto == IPPROTO_ICMP6_) pc = P_ICMP;
    else pc = P_OTHER_IP;
    an->proto[pc].pkts++;
    an->proto[pc].bytes += p->wire_len;

    /* timeline */
    int tl = pc == P_TCP ? TL_TCP : pc == P_UDP ? TL_UDP : TL_OTHER;
    if (p->ts > 0 && an->tl_n > 0) {
        long b = (long)floor((p->ts - an->tl_t0) / an->tl_bucket);
        if (b < 0) b = 0;
        if (b >= an->tl_n) b = an->tl_n - 1;
        an->tl_bytes[tl][b] += p->wire_len;
        an->tl_pkts[tl][b] += 1;
    }

    if (p->l3 == L3_NONE) return;
    if (p->l3 == L3_IPV4) { an->ipv4.pkts++; an->ipv4.bytes += p->wire_len; }
    else { an->ipv6.pkts++; an->ipv6.bytes += p->wire_len; }
    an->ttl_hist[p->ttl]++;
    if (p->is_fragment) an->fragments++;

    host_t *hs = host_get(an, &p->src);
    hs->pkts_tx++;
    hs->bytes_tx += p->wire_len;
    host_t *hd = host_get(an, &p->dst);
    hd->pkts_rx++;
    hd->bytes_rx += p->wire_len;

    if (pc == P_ICMP) {
        int v6 = p->proto == IPPROTO_ICMP6_;
        uint8_t t = p->icmp_type;
        if ((!v6 && t == 3) || (v6 && t == 1)) {
            an->icmp_unreach++;
            host_get(an, &p->src)->icmp_unreach_tx++;
        } else if ((!v6 && t == 8) || (v6 && t == 128)) an->icmp_echo_req++;
        else if ((!v6 && t == 0) || (v6 && t == 129)) an->icmp_echo_rep++;
        else if ((!v6 && t == 11) || (v6 && t == 3)) an->icmp_ttl_exceeded++;
        return;
    }

    if ((pc != P_TCP && pc != P_UDP) || !p->has_l4) return;

    an->size_hist[pc == P_TCP ? 0 : 1][size_bin(p->wire_len)]++;

    int d;
    flow_t *f = flow_get(an, p, &d, o);
    f->last = p->ts > f->last ? p->ts : f->last;
    f->pkts[d]++;
    f->bytes[d] += p->wire_len;
    f->payload[d] += p->payload_len;

    if (pc == P_TCP) {
        uint8_t fl = p->tcp_flags;
        if ((fl & (TCP_SYN | TCP_ACK)) == TCP_SYN) an->flag_count[F_SYN]++;
        if ((fl & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) an->flag_count[F_SYNACK]++;
        if (fl & TCP_ACK) an->flag_count[F_ACK]++;
        if (fl & TCP_PSH) an->flag_count[F_PSH]++;
        if (fl & TCP_FIN) an->flag_count[F_FIN]++;
        if (fl & TCP_RST) an->flag_count[F_RST]++;
        if (fl & TCP_URG) an->flag_count[F_URG]++;
        if (fl & (TCP_ECE | TCP_CWR)) an->flag_count[F_ECE_CWR]++;

        if ((fl & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
            host_get(an, &p->src)->syn_tx++;
            host_t *t = host_get(an, &p->dst);
            if (!t->syn_rx) t->first_syn_rx = p->ts;
            t->syn_rx++;
            t->last_syn_rx = p->ts;
        }
        if (fl & TCP_RST) host_get(an, &p->src)->rst_tx++;
        tcp_update(an, f, d, p);
    } else if (p->sport == 53 || p->dport == 53) {
        dns_parse(an, p);
    }
}

int analysis_add_file(analysis_t *an, const char *path, const analysis_opts_t *o)
{
    VEC_RESERVE(an->files, an->cfiles, (size_t)an->nfiles + 1);
    file_info_t *fi = &an->files[an->nfiles];
    memset(fi, 0, sizeof *fi);
    fi->path = xstrdup(path);
    fi->linktype = -1;

    pcap_reader_t r;
    if (pr_open(&r, path) != 0) {
        fi->error = 1;
        snprintf(fi->errmsg, sizeof fi->errmsg, "%s", r.err);
        pr_close(&r);
        an->nfiles++;
        return -1;
    }
    fi->is_ng = r.is_ng;
    raw_packet_t raw;
    pkt_t pkt;
    int rc;
    while ((rc = pr_next(&r, &raw)) == 1) {
        if (fi->linktype < 0) fi->linktype = raw.linktype;
        decode_packet(&raw, &pkt);
        process_packet(an, &pkt, o);
        fi->packets++;
        fi->bytes += raw.origlen;
    }
    if (rc < 0) {
        fi->error = 1;
        snprintf(fi->errmsg, sizeof fi->errmsg, "%s", r.err);
    }
    fi->truncated_records = r.truncated;
    pr_close(&r);
    an->nfiles++;
    return rc < 0 ? -1 : 0;
}

/* ------------------------------------------------------------------ finish */

uint64_t flow_total_bytes(const flow_t *f) { return f->bytes[0] + f->bytes[1]; }
uint64_t flow_total_pkts(const flow_t *f) { return f->pkts[0] + f->pkts[1]; }

int flow_is_failed_attempt(const flow_t *f)
{
    return f->proto == IPPROTO_TCP_ &&
           (f->state == TCS_REJECTED || f->state == TCS_NO_REPLY || f->state == TCS_HALF_OPEN);
}

static void classify_tcp(flow_t *f)
{
    if (!f->syn_seen && !f->synack_seen) f->state = TCS_MIDSTREAM;
    else if (f->hs_done) {
        if (f->rst[0] || f->rst[1]) f->state = TCS_RESET;
        else if (f->fin[0] || f->fin[1]) f->state = TCS_CLOSED_FIN;
        else f->state = TCS_OPEN;
    } else if (f->synack_seen) f->state = TCS_HALF_OPEN;
    else if (f->rst[1]) f->state = TCS_REJECTED;
    else f->state = TCS_NO_REPLY;
}

void analysis_finish(analysis_t *an)
{
    hmap_t svcmap;
    hmap_init(&svcmap);
    for (size_t i = 0; i < an->nflows; i++) {
        flow_t *f = &an->flows[i];
        if (f->proto == IPPROTO_TCP_) {
            classify_tcp(f);
            an->tcs_count[f->state]++;
        }
        uint8_t key[3] = {f->proto, (uint8_t)(f->sport >> 8), (uint8_t)f->sport};
        int idx = hmap_get(&svcmap, key, 3);
        if (idx < 0) {
            VEC_RESERVE(an->svcs, an->csvcs, an->nsvcs + 1);
            service_t *s = &an->svcs[an->nsvcs];
            memset(s, 0, sizeof *s);
            s->proto = f->proto;
            s->port = f->sport;
            hmap_put(&svcmap, key, 3, (int)an->nsvcs);
            idx = (int)an->nsvcs++;
        }
        service_t *s = &an->svcs[idx];
        s->flows++;
        s->pkts += flow_total_pkts(f);
        s->bytes += flow_total_bytes(f);
    }
    hmap_free(&svcmap);
}

void analysis_free(analysis_t *an)
{
    for (int i = 0; i < an->nfiles; i++) free(an->files[i].path);
    free(an->files);
    for (int s = 0; s < TL_COUNT; s++) { free(an->tl_bytes[s]); free(an->tl_pkts[s]); }
    free(an->flows);
    free(an->hosts);
    free(an->svcs);
    for (size_t i = 0; i < an->ndns; i++) free(an->dns_names[i].name);
    free(an->dns_names);
    hmap_free(&an->flowmap);
    hmap_free(&an->hostmap);
    hmap_free(&an->dnsmap);
}
