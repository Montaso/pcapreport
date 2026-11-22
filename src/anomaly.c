#include "anomaly.h"

#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

const char *const SEV_NAMES[SEV_COUNT] = {"INFO", "NISKI", "ŚREDNI", "WYSOKI"};
const char *const AC_NAMES[AC_COUNT] = {
    "Skanowanie portów", "Skanowanie hostów", "SYN flood", "UDP flood",
    "Niepoprawne flagi TCP", "Nadmiar RST", "Retransmisje TCP", "Zerowe okno TCP",
    "Anomalie DNS", "Beaconing", "Duży transfer", "Ryzykowne usługi", "Jakość przechwytu"};

void detect_opts_default(detect_opts_t *o)
{
    o->scan_ports = 20;
    o->sweep_hosts = 15;
    o->synflood_min = 200;
    o->synflood_rate = 20.0;
    o->udpflood_pps = 500.0;
    o->udpflood_min = 2000;
    o->retrans_pct = 3.0;
    o->beacon_min = 6;
    o->beacon_cv = 0.15;
    o->exfil_bytes = 10ull * 1000 * 1000;
}

void anomaly_list_free(anomaly_list_t *l)
{
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

static anomaly_t *push(anomaly_list_t *l, severity_t sev, anomaly_cat_t cat, uint64_t count,
                       double first, double last)
{
    VEC_RESERVE(l->v, l->cap, l->n + 1);
    anomaly_t *a = &l->v[l->n++];
    memset(a, 0, sizeof *a);
    a->sev = sev;
    a->cat = cat;
    a->count = count;
    a->first = first;
    a->last = last;
    return a;
}

#define TITLE(a, ...) snprintf((a)->title, sizeof (a)->title, __VA_ARGS__)
#define DETAIL(a, ...) snprintf((a)->detail, sizeof (a)->detail, __VA_ARGS__)

static void detail_append(anomaly_t *a, const char *fmt, ...)
{
    size_t l = strlen(a->detail);
    if (l + 1 >= sizeof a->detail) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(a->detail + l, sizeof a->detail - l, fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------ sorting */

static const analysis_t *g_an;
#define FL(i) (&g_an->flows[i])

static int cmp_d(double a, double b) { return a < b ? -1 : a > b; }

/* (proto, cli, srv, sport, first) */
static int cmp_cli_srv(const void *pa, const void *pb)
{
    const flow_t *x = FL(*(const size_t *)pa), *y = FL(*(const size_t *)pb);
    if (x->proto != y->proto) return x->proto < y->proto ? -1 : 1;
    int c = addr_cmp(&x->cli, &y->cli);
    if (c) return c;
    if ((c = addr_cmp(&x->srv, &y->srv))) return c;
    if (x->sport != y->sport) return x->sport < y->sport ? -1 : 1;
    return cmp_d(x->first, y->first);
}

/* (proto, cli, sport, srv) */
static int cmp_cli_port(const void *pa, const void *pb)
{
    const flow_t *x = FL(*(const size_t *)pa), *y = FL(*(const size_t *)pb);
    if (x->proto != y->proto) return x->proto < y->proto ? -1 : 1;
    int c = addr_cmp(&x->cli, &y->cli);
    if (c) return c;
    if (x->sport != y->sport) return x->sport < y->sport ? -1 : 1;
    return addr_cmp(&x->srv, &y->srv);
}

/* (proto, srv, sport, cli) */
static int cmp_srv_port(const void *pa, const void *pb)
{
    const flow_t *x = FL(*(const size_t *)pa), *y = FL(*(const size_t *)pb);
    if (x->proto != y->proto) return x->proto < y->proto ? -1 : 1;
    int c = addr_cmp(&x->srv, &y->srv);
    if (c) return c;
    if (x->sport != y->sport) return x->sport < y->sport ? -1 : 1;
    return addr_cmp(&x->cli, &y->cli);
}

/* (proto, srv, cli) */
static int cmp_srv_cli(const void *pa, const void *pb)
{
    const flow_t *x = FL(*(const size_t *)pa), *y = FL(*(const size_t *)pb);
    if (x->proto != y->proto) return x->proto < y->proto ? -1 : 1;
    int c = addr_cmp(&x->srv, &y->srv);
    if (c) return c;
    return addr_cmp(&x->cli, &y->cli);
}

static size_t *sorted_flows(const analysis_t *an, int (*cmp)(const void *, const void *))
{
    size_t *idx = xmalloc(an->nflows * sizeof(size_t) + 1);
    for (size_t i = 0; i < an->nflows; i++) idx[i] = i;
    g_an = an;
    qsort(idx, an->nflows, sizeof(size_t), cmp);
    return idx;
}

/* ------------------------------------------------------------ helpers */

/* a flow that looks like a probe rather than a real conversation */
static int is_probe(const flow_t *f)
{
    if (f->proto == IPPROTO_TCP_) {
        if (flow_is_failed_attempt(f) || f->bad_flags) return 1;
        uint64_t pl = f->payload[0] + f->payload[1];
        if (f->state == TCS_MIDSTREAM && pl == 0 && flow_total_pkts(f) <= 3) return 1;
        if (f->hs_done && pl == 0 && flow_total_pkts(f) <= 5) return 1; /* connect() scan */
        return 0;
    }
    return f->pkts[1] == 0 && f->pkts[0] <= 2;
}

static const char *ep(const addr_t *a, uint16_t port, char *buf, size_t len)
{
    char s[64];
    addr_str(a, s, sizeof s);
    if (a->ver == 6) snprintf(buf, len, "[%s]:%u", s, port);
    else snprintf(buf, len, "%s:%u", s, port);
    return buf;
}

static const char *proto_name(uint8_t p) { return p == IPPROTO_TCP_ ? "TCP" : "UDP"; }

/* ------------------------------------------------------------ detectors */

static void detect_vertical_scan(const analysis_t *an, const detect_opts_t *o, anomaly_list_t *out)
{
    size_t *idx = sorted_flows(an, cmp_cli_srv);
    size_t i = 0;
    while (i < an->nflows) {
        const flow_t *g = FL(idx[i]);
        size_t j = i;
        int ports = 0, probe_ports = 0, open_ports = 0;
        int n_syn = 0, n_connect = 0, n_stealth = 0, silent_ports = 0, silent_listed = 0;
        char silentlist[160] = "";
        size_t sl = 0;
        uint16_t pmin = 65535, pmax = 0;
        double t0 = g->first, t1 = g->last;
        char openlist[160] = "";
        size_t ol = 0;
        int open_listed = 0;
        while (j < an->nflows) {
            const flow_t *f = FL(idx[j]);
            if (f->proto != g->proto || addr_cmp(&f->cli, &g->cli) || addr_cmp(&f->srv, &g->srv)) break;
            /* one port may have several flows */
            uint16_t port = f->sport;
            int any_probe = 0, any_open = 0, any_reply = 0;
            while (j < an->nflows) {
                const flow_t *h = FL(idx[j]);
                if (h->proto != g->proto || addr_cmp(&h->cli, &g->cli) || addr_cmp(&h->srv, &g->srv) ||
                    h->sport != port)
                    break;
                if (is_probe(h)) any_probe = 1;
                if (h->pkts[1] > 0) any_reply = 1;
                if (h->proto == IPPROTO_TCP_) {
                    if (h->synack_seen || h->hs_done) any_open = 1;
                    if (h->bad_flags || (h->state == TCS_MIDSTREAM && (h->flags_seen[0] & TCP_FIN))) n_stealth++;
                    else if (h->hs_done) n_connect++;
                    else n_syn++;
                } else if (h->pkts[1] > 0) {
                    any_open = 1;
                }
                if (h->first < t0) t0 = h->first;
                if (h->last > t1) t1 = h->last;
                j++;
            }
            ports++;
            if (any_probe) probe_ports++;
            if (any_open) {
                open_ports++;
                if (open_listed < 12 && ol + 8 < sizeof openlist) {
                    ol += (size_t)snprintf(openlist + ol, sizeof openlist - ol, "%s%u", ol ? ", " : "", port);
                    open_listed++;
                }
            }
            if (!any_reply) {
                silent_ports++;
                if (silent_listed < 12 && sl + 8 < sizeof silentlist) {
                    sl += (size_t)snprintf(silentlist + sl, sizeof silentlist - sl, "%s%u", sl ? ", " : "", port);
                    silent_listed++;
                }
            }
            if (port < pmin) pmin = port;
            if (port > pmax) pmax = port;
        }

        if (ports >= o->scan_ports && probe_ports * 10 >= ports * 6) {
            char c[64], s[64];
            addr_str(&g->cli, c, sizeof c);
            addr_str(&g->srv, s, sizeof s);
            int tcp = g->proto == IPPROTO_TCP_;
            severity_t sev = tcp || ports >= 2 * o->scan_ports ? SEV_HIGH : SEV_MEDIUM;
            anomaly_t *a = push(out, sev, AC_PORTSCAN, (uint64_t)ports, t0, t1);
            TITLE(a, "Skanowanie portów %s: %s -> %s", proto_name(g->proto), c, s);
            const char *tech;
            if (!tcp) tech = "skan UDP";
            else if (n_stealth > n_syn && n_stealth > n_connect) tech = "skan FIN/NULL/XMAS (stealth)";
            else if (n_connect > n_syn) tech = "skan pełnym połączeniem (connect)";
            else tech = "skan SYN (half-open)";
            DETAIL(a, "%d różnych portów docelowych (zakres %u-%u), %d prób bez nawiązania sesji. "
                      "Technika: %s. ",
                   ports, pmin, pmax, probe_ports, tech);
            if (open_ports)
                detail_append(a, "Porty odpowiadające (%d): %s%s.", open_ports, openlist,
                              open_ports > open_listed ? ", ..." : "");
            else
                detail_append(a, "Żaden port nie odpowiedział pozytywnie. ");
            int stealth = !tcp || (n_stealth > n_syn && n_stealth > n_connect);
            if (stealth && silent_ports && silent_ports < ports)
                detail_append(a, "Porty bez żadnej odpowiedzi - otwarte lub filtrowane (%d): %s%s.", silent_ports,
                              silentlist, silent_ports > silent_listed ? ", ..." : "");
        }
        i = j;
    }
    free(idx);
}

static void detect_sweep(const analysis_t *an, const detect_opts_t *o, anomaly_list_t *out)
{
    size_t *idx = sorted_flows(an, cmp_cli_port);
    size_t i = 0;
    while (i < an->nflows) {
        const flow_t *g = FL(idx[i]);
        size_t j = i;
        int hosts = 0, probes = 0, answered = 0;
        double t0 = g->first, t1 = g->last;
        const addr_t *prev = NULL;
        while (j < an->nflows) {
            const flow_t *f = FL(idx[j]);
            if (f->proto != g->proto || addr_cmp(&f->cli, &g->cli) || f->sport != g->sport) break;
            if (!addr_is_multicast(&f->srv) && (!prev || addr_cmp(prev, &f->srv))) {
                hosts++;
                if (is_probe(f)) probes++;
                if (f->proto == IPPROTO_TCP_ ? (f->synack_seen != 0) : (f->pkts[1] > 0)) answered++;
                prev = &f->srv;
            }
            if (f->first < t0) t0 = f->first;
            if (f->last > t1) t1 = f->last;
            j++;
        }
        if (hosts >= o->sweep_hosts && probes * 10 >= hosts * 6) {
            char c[64];
            addr_str(&g->cli, c, sizeof c);
            const char *svc = service_name(g->proto, g->sport);
            anomaly_t *a = push(out, g->proto == IPPROTO_TCP_ ? SEV_HIGH : SEV_MEDIUM, AC_SWEEP,
                                (uint64_t)hosts, t0, t1);
            TITLE(a, "Skanowanie hostów %s/%u%s%s%s: źródło %s", proto_name(g->proto), g->sport,
                  svc ? " (" : "", svc ? svc : "", svc ? ")" : "", c);
            DETAIL(a, "Host %s próbował połączyć się z %d różnymi hostami na porcie %u; "
                      "%d prób wyglądało na sondowanie, odpowiedziało %d hostów.",
                   c, hosts, g->sport, probes, answered);
        }
        i = j;
    }
    free(idx);
}

static void detect_synflood(const analysis_t *an, const detect_opts_t *o, anomaly_list_t *out)
{
    size_t *idx = sorted_flows(an, cmp_srv_port);
    size_t i = 0;
    while (i < an->nflows) {
        const flow_t *g = FL(idx[i]);
        size_t j = i;
        uint64_t failed = 0, total = 0, syns = 0;
        int clients = 0, failed_clients = 0;
        double t0 = 0, t1 = 0;
        const addr_t *prev = NULL;
        int prev_failed_counted = 0;
        while (j < an->nflows) {
            const flow_t *f = FL(idx[j]);
            if (f->proto != g->proto || addr_cmp(&f->srv, &g->srv) || f->sport != g->sport) break;
            int newcli = !prev || addr_cmp(prev, &f->cli);
            if (newcli) { clients++; prev = &f->cli; prev_failed_counted = 0; }
            total++;
            if (flow_is_failed_attempt(f)) {
                failed++;
                syns += f->syn_count;
                if (!prev_failed_counted) { failed_clients++; prev_failed_counted = 1; }
                if (t0 == 0 || f->first < t0) t0 = f->first;
                if (f->last > t1) t1 = f->last;
            }
            j++;
        }
        if (g->proto == IPPROTO_TCP_ && failed >= (uint64_t)o->synflood_min && failed * 10 >= total * 5) {
            double span = t1 - t0;
            double rate = (double)syns / (span > 1.0 ? span : 1.0);
            if (rate >= o->synflood_rate) {
                char s[80];
                ep(&g->srv, g->sport, s, sizeof s);
                anomaly_t *a = push(out, SEV_HIGH, AC_SYNFLOOD, failed, t0, t1);
                TITLE(a, "Możliwy atak SYN flood na %s", s);
                DETAIL(a, "%llu z %llu połączeń TCP do usługi nie zostało ustanowionych "
                          "(%llu pakietów SYN, średnio %.0f SYN/s). Liczba różnych źródeł: %d%s.",
                       (unsigned long long)failed, (unsigned long long)total,
                       (unsigned long long)syns, rate, failed_clients,
                       failed_clients > 50 ? " - prawdopodobnie sfałszowane adresy (spoofing)" : "");
            }
        }
        i = j;
    }
    free(idx);
}

static void detect_udpflood(const analysis_t *an, const detect_opts_t *o, anomaly_list_t *out)
{
    size_t *idx = sorted_flows(an, cmp_srv_cli);
    size_t i = 0;
    while (i < an->nflows) {
        const flow_t *g = FL(idx[i]);
        size_t j = i;
        uint64_t pkts = 0, bytes = 0, reply = 0;
        int clients = 0, ports_cnt = 0;
        double t0 = g->first, t1 = g->last;
        const addr_t *prev = NULL;
        while (j < an->nflows) {
            const flow_t *f = FL(idx[j]);
            if (f->proto != g->proto || addr_cmp(&f->srv, &g->srv)) break;
            if (!prev || addr_cmp(prev, &f->cli)) { clients++; prev = &f->cli; }
            pkts += f->pkts[0];
            bytes += f->bytes[0];
            reply += f->pkts[1];
            ports_cnt++;
            if (f->first < t0) t0 = f->first;
            if (f->last > t1) t1 = f->last;
            j++;
        }
        if (g->proto == IPPROTO_UDP_ && pkts >= o->udpflood_min) {
            double span = t1 - t0;
            double pps = (double)pkts / (span > 1.0 ? span : 1.0);
            if (pps >= o->udpflood_pps && reply * 10 < pkts) {
                char s[64], b[32], br[32];
                addr_str(&g->srv, s, sizeof s);
                anomaly_t *a = push(out, clients > 1 ? SEV_HIGH : SEV_MEDIUM, AC_UDPFLOOD, pkts, t0, t1);
                TITLE(a, "Możliwy UDP flood na %s", s);
                DETAIL(a, "%llu pakietów UDP (%s) w %.1f s - średnio %.0f pakietów/s (%s), "
                          "liczba źródeł: %d, przepływów: %d, pakietów odpowiedzi: %llu.",
                       (unsigned long long)pkts, fmt_bytes((double)bytes, b, sizeof b), span, pps,
                       fmt_bitrate((double)bytes * 8.0 / (span > 1.0 ? span : 1.0), br, sizeof br),
                       clients, ports_cnt, (unsigned long long)reply);
            }
        }
        i = j;
    }
    free(idx);
}

static void detect_badflags(const analysis_t *an, anomaly_list_t *out)
{
    for (size_t h = 0; h < an->nhosts; h++) {
        const host_t *ho = &an->hosts[h];
        if (!ho->bad_flags_tx) continue;
        uint8_t mask = 0;
        double t0 = 0, t1 = 0;
        int targets = 0;
        for (size_t i = 0; i < an->nflows; i++) {
            const flow_t *f = &an->flows[i];
            if (!f->bad_flags) continue;
            if (addr_cmp(&f->cli, &ho->a) && addr_cmp(&f->srv, &ho->a)) continue;
            mask |= f->bad_flags;
            targets++;
            if (t0 == 0 || f->first < t0) t0 = f->first;
            if (f->last > t1) t1 = f->last;
        }
        char s[64], kinds[128] = "";
        addr_str(&ho->a, s, sizeof s);
        size_t kl = 0;
        for (int b = 0; b < BF_COUNT; b++)
            if (mask & (1u << b))
                kl += (size_t)snprintf(kinds + kl, sizeof kinds - kl, "%s%s", kl ? ", " : "", BADFLAG_NAMES[b]);
        anomaly_t *a = push(out, SEV_HIGH, AC_BADFLAGS, ho->bad_flags_tx, t0, t1);
        TITLE(a, "Niedozwolone kombinacje flag TCP z hosta %s", s);
        DETAIL(a, "Host wysłał %llu pakietów TCP z flagami niezgodnymi z RFC 793 (%s) w %d przepływach. "
                  "Takie pakiety nie występują w normalnym ruchu - typowe dla skanerów "
                  "(np. nmap -sN/-sX/-sF) lub prób omijania zapór.",
               (unsigned long long)ho->bad_flags_tx, kinds, targets);
    }
}

static void detect_rst(const analysis_t *an, anomaly_list_t *out)
{
    for (size_t h = 0; h < an->nhosts; h++) {
        const host_t *ho = &an->hosts[h];
        if (ho->rst_tx < 100 || ho->rst_tx * 10 < ho->pkts_tx * 3) continue;
        char s[64];
        addr_str(&ho->a, s, sizeof s);
        anomaly_t *a = push(out, SEV_MEDIUM, AC_RST, ho->rst_tx, 0, 0);
        TITLE(a, "Duża liczba pakietów RST wysyłanych przez %s", s);
        DETAIL(a, "%llu z %llu pakietów wysłanych przez host to TCP RST (%.0f%%). Oznacza to masowe "
                  "odrzucanie połączeń - często jest to odpowiedź na skanowanie portów lub "
                  "efekt awarii usługi.",
               (unsigned long long)ho->rst_tx, (unsigned long long)ho->pkts_tx,
               100.0 * (double)ho->rst_tx / (double)ho->pkts_tx);
    }
}

static int cmp_retrans(const void *pa, const void *pb)
{
    const flow_t *x = FL(*(const size_t *)pa), *y = FL(*(const size_t *)pb);
    uint32_t rx = x->retrans[0] + x->retrans[1], ry = y->retrans[0] + y->retrans[1];
    return rx < ry ? 1 : rx > ry ? -1 : 0;
}

static void detect_retrans(const analysis_t *an, const detect_opts_t *o, anomaly_list_t *out)
{
    if (an->tcp_data_segs < 50) return;
    double pct = 100.0 * (double)an->tcp_retrans / (double)an->tcp_data_segs;

    size_t *idx = sorted_flows(an, cmp_retrans);
    char worst[400] = "";
    size_t wl = 0;
    int listed = 0;
    for (size_t i = 0; i < an->nflows && listed < 3; i++) {
        const flow_t *f = FL(idx[i]);
        uint32_t r = f->retrans[0] + f->retrans[1];
        uint32_t ds = f->data_segs[0] + f->data_segs[1];
        if (f->proto != IPPROTO_TCP_ || r < 5 || ds == 0) break;
        char c[80], s[80];
        wl += (size_t)snprintf(worst + wl, sizeof worst - wl, "%s%s -> %s: %u retransmisji (%.0f%%)",
                               listed ? "; " : "", ep(&f->cli, f->cport, c, sizeof c),
                               ep(&f->srv, f->sport, s, sizeof s), r, 100.0 * r / (double)ds);
        listed++;
    }
    free(idx);

    if (pct >= o->retrans_pct) {
        anomaly_t *a = push(out, pct >= 3 * o->retrans_pct ? SEV_HIGH : SEV_MEDIUM, AC_RETRANS,
                            an->tcp_retrans, 0, 0);
        TITLE(a, "Wysoki poziom retransmisji TCP: %.1f%% segmentów z danymi", pct);
        DETAIL(a, "%llu retransmisji na %llu segmentów z danymi (próg %.1f%%). Wskazuje to na utratę "
                  "pakietów, przeciążenie łącza lub problemy z MTU. Najbardziej dotknięte: %s.",
               (unsigned long long)an->tcp_retrans, (unsigned long long)an->tcp_data_segs,
               o->retrans_pct, listed ? worst : "brak");
    } else if (listed) {
        anomaly_t *a = push(out, SEV_LOW, AC_RETRANS, an->tcp_retrans, 0, 0);
        TITLE(a, "Pojedyncze połączenia z retransmisjami TCP");
        DETAIL(a, "Globalny poziom retransmisji jest akceptowalny (%.2f%%), ale występują połączenia "
                  "z powtórzeniami: %s.",
               pct, worst);
    }
}

static void detect_zerowin(const analysis_t *an, anomaly_list_t *out)
{
    int n = 0;
    uint64_t events = 0;
    char ex[300] = "";
    size_t el = 0;
    for (size_t i = 0; i < an->nflows; i++) {
        const flow_t *f = &an->flows[i];
        uint32_t z = f->zero_win[0] + f->zero_win[1];
        if (z < 3) continue;
        n++;
        events += z;
        if (n <= 3) {
            char c[80], s[80];
            el += (size_t)snprintf(ex + el, sizeof ex - el, "%s%s -> %s (%u)", n > 1 ? "; " : "",
                                   ep(&f->cli, f->cport, c, sizeof c), ep(&f->srv, f->sport, s, sizeof s), z);
        }
    }
    if (!n) return;
    anomaly_t *a = push(out, SEV_LOW, AC_ZEROWIN, events, 0, 0);
    TITLE(a, "Zerowe okno odbiorcze TCP w %d połączeniach", n);
    DETAIL(a, "Odbiorca ogłaszał okno 0 (%llu razy) - aplikacja nie nadąża z odbiorem danych, "
              "co spowalnia transmisję. Przykłady: %s.",
           (unsigned long long)events, ex);
}

typedef struct {
    char    *base;
    int      unique, suspicious;
    uint64_t queries;
    char     example[128];
    addr_t   client;
} dns_base_t;

static const char *base_domain(const char *name)
{
    const char *p = name + strlen(name);
    int dots = 0;
    while (p > name) {
        p--;
        if (*p == '.' && ++dots == 2) return p + 1;
    }
    return name;
}

static void detect_dns(const analysis_t *an, anomaly_list_t *out)
{
    if (!an->ndns) return;
    hmap_t m;
    hmap_init(&m);
    dns_base_t *b = NULL;
    size_t nb = 0, cb = 0;
    for (size_t i = 0; i < an->ndns; i++) {
        const dns_name_t *d = &an->dns_names[i];
        const char *base = base_domain(d->name);
        int idx = hmap_get(&m, base, strlen(base));
        if (idx < 0) {
            VEC_RESERVE(b, cb, nb + 1);
            memset(&b[nb], 0, sizeof b[nb]);
            b[nb].base = xstrdup(base);
            hmap_put(&m, base, strlen(base), (int)nb);
            idx = (int)nb++;
        }
        dns_base_t *e = &b[idx];
        e->unique++;
        e->queries += d->queries;
        size_t len = strlen(d->name);
        int susp = d->longest_label >= 40 || len >= 90 || (d->entropy >= 3.8 && d->longest_label >= 24);
        if (susp) {
            if (!e->suspicious) {
                snprintf(e->example, sizeof e->example, "%.100s%s", d->name, len > 100 ? "..." : "");
                e->client = d->first_client;
            }
            e->suspicious++;
        }
    }
    for (size_t i = 0; i < nb; i++) {
        dns_base_t *e = &b[i];
        char c[64];
        addr_str(&e->client, c, sizeof c);
        if (e->suspicious >= 5) {
            anomaly_t *a = push(out, SEV_HIGH, AC_DNS, (uint64_t)e->suspicious, 0, 0);
            TITLE(a, "Możliwy tunel DNS / eksfiltracja przez domenę %s", e->base);
            DETAIL(a, "%d unikalnych zapytań o długie, losowo wyglądające subdomeny (łącznie %d nazw w "
                      "domenie, %llu zapytań). Pierwszy klient: %s. Przykład: %s",
                   e->suspicious, e->unique, (unsigned long long)e->queries, c, e->example);
        } else if (e->suspicious > 0) {
            anomaly_t *a = push(out, SEV_LOW, AC_DNS, (uint64_t)e->suspicious, 0, 0);
            TITLE(a, "Nietypowo długie nazwy DNS w domenie %s", e->base);
            DETAIL(a, "%d nazw o długich/wysokoentropijnych etykietach. Klient: %s. Przykład: %s",
                   e->suspicious, c, e->example);
        } else if (e->unique >= 100) {
            anomaly_t *a = push(out, SEV_MEDIUM, AC_DNS, (uint64_t)e->unique, 0, 0);
            TITLE(a, "Bardzo wiele unikalnych subdomen w %s", e->base);
            DETAIL(a, "%d różnych nazw w jednej domenie (%llu zapytań) - możliwy tunel DNS lub DGA.",
                   e->unique, (unsigned long long)e->queries);
        }
        free(e->base);
    }
    free(b);
    hmap_free(&m);

    if (an->dns_responses >= 20 && an->dns_nxdomain * 4 >= an->dns_responses) {
        char ex[256] = "";
        size_t el = 0;
        int listed = 0;
        for (size_t i = 0; i < an->ndns && listed < 4; i++) {
            if (!an->dns_names[i].nxdomain) continue;
            el += (size_t)snprintf(ex + el, sizeof ex - el, "%s%.48s", listed ? ", " : "", an->dns_names[i].name);
            listed++;
        }
        anomaly_t *a = push(out, SEV_MEDIUM, AC_DNS, an->dns_nxdomain, 0, 0);
        TITLE(a, "Wysoki odsetek odpowiedzi NXDOMAIN: %.0f%%",
              100.0 * (double)an->dns_nxdomain / (double)an->dns_responses);
        DETAIL(a, "%llu z %llu odpowiedzi DNS to NXDOMAIN (nieistniejąca domena). Może to wskazywać na "
                  "złośliwe oprogramowanie z algorytmem DGA lub błędną konfigurację. Przykłady: %s.",
               (unsigned long long)an->dns_nxdomain, (unsigned long long)an->dns_responses, ex);
    }
}

static int is_periodic_service(uint16_t port)
{
    return port == 53 || port == 123 || port == 5353 || port == 1900 || port == 137 || port == 138 ||
           port == 67 || port == 68 || port == 5355;
}

static void detect_beacon(const analysis_t *an, const detect_opts_t *o, anomaly_list_t *out)
{
    size_t *idx = sorted_flows(an, cmp_cli_srv);
    double *iv = xmalloc(sizeof(double) * (an->nflows + 1));
    size_t i = 0;
    while (i < an->nflows) {
        const flow_t *g = FL(idx[i]);
        size_t j = i + 1;
        while (j < an->nflows) {
            const flow_t *f = FL(idx[j]);
            if (f->proto != g->proto || addr_cmp(&f->cli, &g->cli) || addr_cmp(&f->srv, &g->srv) ||
                f->sport != g->sport)
                break;
            j++;
        }
        size_t n = j - i;
        if ((int)n >= o->beacon_min && !is_periodic_service(g->sport)) {
            double sum = 0;
            for (size_t k = 1; k < n; k++) { iv[k - 1] = FL(idx[i + k])->first - FL(idx[i + k - 1])->first; sum += iv[k - 1]; }
            double mean = sum / (double)(n - 1);
            double var = 0;
            for (size_t k = 0; k + 1 < n; k++) var += (iv[k] - mean) * (iv[k] - mean);
            double sd = sqrt(var / (double)(n - 1));
            double cv = mean > 0 ? sd / mean : 1e9;
            if (mean >= 1.0 && cv <= o->beacon_cv) {
                char c[64], s[80];
                addr_str(&g->cli, c, sizeof c);
                ep(&g->srv, g->sport, s, sizeof s);
                uint64_t bytes = 0;
                for (size_t k = 0; k < n; k++) bytes += flow_total_bytes(FL(idx[i + k]));
                anomaly_t *a = push(out, SEV_MEDIUM, AC_BEACON, n, g->first, FL(idx[j - 1])->first);
                TITLE(a, "Regularne połączenia (beaconing): %s -> %s %s", c, s, proto_name(g->proto));
                DETAIL(a, "%zu połączeń w stałych odstępach: średnio %.1f s (odchylenie %.2f s, CV=%.3f). "
                          "Średnio %.0f B na połączenie. Tak regularny rytm jest typowy dla "
                          "komunikacji malware z serwerem C2 (lub automatycznych zadań).",
                       n, mean, sd, cv, (double)bytes / (double)n);
            }
        }
        i = j;
    }
    free(iv);
    free(idx);
}

static void detect_exfil(const analysis_t *an, const detect_opts_t *o, anomaly_list_t *out)
{
    for (size_t i = 0; i < an->nflows; i++) {
        const flow_t *f = &an->flows[i];
        if (f->payload[0] < o->exfil_bytes || f->payload[0] < 4 * f->payload[1]) continue;
        char c[80], s[80], b[32], r[32];
        double dur = f->last - f->first;
        int pub = !addr_is_private(&f->srv);
        anomaly_t *a = push(out, pub ? SEV_MEDIUM : SEV_LOW, AC_EXFIL, f->payload[0], f->first, f->last);
        TITLE(a, "Duży transfer wychodzący %s -> %s", ep(&f->cli, f->cport, c, sizeof c),
              ep(&f->srv, f->sport, s, sizeof s));
        DETAIL(a, "Klient wysłał %s danych (%s, %.0fx więcej niż odebrał) w ciągu %.1f s do adresu %s. "
                  "Warto zweryfikować, czy to autoryzowana kopia/upload, a nie eksfiltracja.",
               fmt_bytes((double)f->payload[0], b, sizeof b),
               fmt_bitrate(dur > 0 ? (double)f->payload[0] * 8.0 / dur : 0, r, sizeof r),
               f->payload[1] ? (double)f->payload[0] / (double)f->payload[1] : 999.0, dur,
               pub ? "publicznego" : "prywatnego");
    }
}

static void detect_ports(const analysis_t *an, anomaly_list_t *out)
{
    static const struct { uint8_t proto; uint16_t port; severity_t sev; const char *why; } R[] = {
        {6, 23, SEV_MEDIUM, "Telnet przesyła hasła i sesję otwartym tekstem"},
        {6, 21, SEV_LOW, "FTP przesyła dane logowania otwartym tekstem"},
        {6, 110, SEV_LOW, "POP3 bez TLS ujawnia dane logowania"},
        {6, 143, SEV_LOW, "IMAP bez TLS ujawnia dane logowania"},
        {17, 69, SEV_LOW, "TFTP nie ma uwierzytelniania"},
        {17, 161, SEV_LOW, "SNMP v1/v2c używa jawnych community strings"},
        {6, 80, SEV_INFO, "HTTP bez szyfrowania"},
        {6, 4444, SEV_HIGH, "port domyślny Metasploit / reverse shell"},
        {6, 31337, SEV_HIGH, "port kojarzony z backdoorami (Back Orifice / elite)"},
        {6, 1337, SEV_MEDIUM, "port często używany przez narzędzia ofensywne"},
        {6, 6667, SEV_MEDIUM, "IRC - historycznie kanał C2 botnetów"},
        {6, 12345, SEV_MEDIUM, "port kojarzony z trojanem NetBus"},
    };
    for (size_t r = 0; r < ARRAY_LEN(R); r++) {
        uint32_t real = 0;
        uint64_t bytes = 0;
        double t0 = 0, t1 = 0;
        for (size_t i = 0; i < an->nflows; i++) {
            const flow_t *f = &an->flows[i];
            if (f->proto != R[r].proto || f->sport != R[r].port) continue;
            int ok = f->proto == IPPROTO_TCP_ ? (f->hs_done && (f->payload[0] + f->payload[1]) > 0)
                                              : f->pkts[1] > 0;
            if (!ok) continue;
            real++;
            bytes += flow_total_bytes(f);
            if (t0 == 0 || f->first < t0) t0 = f->first;
            if (f->last > t1) t1 = f->last;
        }
        if (!real) continue;
        char b[32];
        anomaly_t *a = push(out, R[r].sev, AC_PORTS, real, t0, t1);
        const char *nm = service_name(R[r].proto, R[r].port);
        TITLE(a, "Ruch usługi %s (%s/%u)", nm ? nm : "?", proto_name(R[r].proto), R[r].port);
        DETAIL(a, "Aktywne sesje z wymianą danych: %u (%s). Uwaga: %s.", real,
               fmt_bytes((double)bytes, b, sizeof b), R[r].why);
    }
}

static void detect_capture(const analysis_t *an, anomaly_list_t *out)
{
    uint64_t bad = an->truncated + an->malformed;
    if (bad) {
        anomaly_t *a = push(out, an->malformed ? SEV_LOW : SEV_INFO, AC_CAPTURE, bad, 0, 0);
        TITLE(a, "Pakiety obcięte lub uszkodzone: %llu", (unsigned long long)bad);
        DETAIL(a, "%llu pakietów krótszych niż deklarują nagłówki (np. mały snaplen) oraz %llu z "
                  "niepoprawnymi polami nagłówka (możliwe celowo spreparowane pakiety).",
               (unsigned long long)an->truncated, (unsigned long long)an->malformed);
    }
    if (an->fragments) {
        anomaly_t *a = push(out, an->fragments > 100 ? SEV_LOW : SEV_INFO, AC_CAPTURE, an->fragments, 0, 0);
        TITLE(a, "Fragmentacja IP: %llu fragmentów", (unsigned long long)an->fragments);
        DETAIL(a, "Fragmenty IP (poza pierwszym) nie niosą nagłówka L4, więc nie są przypisywane do "
                  "przepływów. Duża liczba fragmentów może oznaczać problemy z MTU lub próbę omijania IDS.");
    }
    if (an->unsupported_link) {
        anomaly_t *a = push(out, SEV_INFO, AC_CAPTURE, an->unsupported_link, 0, 0);
        TITLE(a, "Nieobsługiwany typ warstwy łącza: %llu pakietów", (unsigned long long)an->unsupported_link);
        DETAIL(a, "Część pakietów ma typ łącza, którego narzędzie nie dekoduje - zostały tylko policzone.");
    }
    for (int i = 0; i < an->nfiles; i++) {
        const file_info_t *f = &an->files[i];
        if (!f->error && !f->truncated_records) continue;
        anomaly_t *a = push(out, SEV_INFO, AC_CAPTURE, f->truncated_records, 0, 0);
        TITLE(a, "Problem z plikiem %s", f->path);
        if (f->error) DETAIL(a, "Odczyt przerwany: %s. Przeanalizowano %llu pakietów.", f->errmsg, (unsigned long long)f->packets);
        else DETAIL(a, "Plik kończy się niepełnym rekordem (prawdopodobnie przerwany zapis). Przeanalizowano %llu pakietów.",
                    (unsigned long long)f->packets);
    }
}

static int cmp_anom(const void *pa, const void *pb)
{
    const anomaly_t *x = pa, *y = pb;
    if (x->sev != y->sev) return x->sev > y->sev ? -1 : 1;
    if (x->cat != y->cat) return x->cat < y->cat ? -1 : 1;
    return x->count > y->count ? -1 : x->count < y->count;
}

void detect_anomalies(analysis_t *an, const detect_opts_t *o, anomaly_list_t *out)
{
    memset(out, 0, sizeof *out);
    detect_vertical_scan(an, o, out);
    detect_sweep(an, o, out);
    detect_synflood(an, o, out);
    detect_udpflood(an, o, out);
    detect_badflags(an, out);
    detect_rst(an, out);
    detect_retrans(an, o, out);
    detect_zerowin(an, out);
    detect_dns(an, out);
    detect_beacon(an, o, out);
    detect_exfil(an, o, out);
    detect_ports(an, out);
    detect_capture(an, out);
    if (out->n) qsort(out->v, out->n, sizeof(anomaly_t), cmp_anom);
}
