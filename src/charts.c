#include "charts.h"
#include "chart.h"
#include "png.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#define CW 1200
#define CHH 560

const char *const RTT_BIN_LABELS[RTT_BINS] = {"<0.1", "0.1-0.5", "0.5-1", "1-5", "5-10",
                                              "10-50", "50-100", "100-500", ">=500"};

int rtt_bin(double ms)
{
    static const double edges[RTT_BINS - 1] = {0.1, 0.5, 1, 5, 10, 50, 100, 500};
    for (int i = 0; i < RTT_BINS - 1; i++)
        if (ms < edges[i]) return i;
    return RTT_BINS - 1;
}

rgb_t severity_color(int sev)
{
    switch (sev) {
    case SEV_HIGH: return C_CRITICAL;
    case SEV_MEDIUM: return C_SERIOUS;
    case SEV_LOW: return C_WARNING;
    default: return C_MUTED;
    }
}

/* ------------------------------------------------------------ sorting helpers */

static const analysis_t *g_an;

static int cmp_host(const void *a, const void *b)
{
    const host_t *x = &g_an->hosts[*(const size_t *)a], *y = &g_an->hosts[*(const size_t *)b];
    uint64_t tx = x->bytes_tx + x->bytes_rx, ty = y->bytes_tx + y->bytes_rx;
    return tx < ty ? 1 : tx > ty ? -1 : 0;
}

static int cmp_svc(const void *a, const void *b)
{
    const service_t *x = &g_an->svcs[*(const size_t *)a], *y = &g_an->svcs[*(const size_t *)b];
    if (x->bytes != y->bytes) return x->bytes < y->bytes ? 1 : -1;
    return x->flows < y->flows ? 1 : x->flows > y->flows ? -1 : 0;
}

static int cmp_flow(const void *a, const void *b)
{
    uint64_t x = flow_total_bytes(&g_an->flows[*(const size_t *)a]);
    uint64_t y = flow_total_bytes(&g_an->flows[*(const size_t *)b]);
    return x < y ? 1 : x > y ? -1 : 0;
}

size_t *top_hosts(const analysis_t *an, size_t *n)
{
    size_t *idx = xmalloc(sizeof(size_t) * (an->nhosts + 1));
    for (size_t i = 0; i < an->nhosts; i++) idx[i] = i;
    g_an = an;
    qsort(idx, an->nhosts, sizeof(size_t), cmp_host);
    *n = an->nhosts;
    return idx;
}

size_t *top_services(const analysis_t *an, size_t *n)
{
    size_t *idx = xmalloc(sizeof(size_t) * (an->nsvcs + 1));
    for (size_t i = 0; i < an->nsvcs; i++) idx[i] = i;
    g_an = an;
    qsort(idx, an->nsvcs, sizeof(size_t), cmp_svc);
    *n = an->nsvcs;
    return idx;
}

size_t *top_flows(const analysis_t *an, uint8_t proto, size_t *n)
{
    size_t *idx = xmalloc(sizeof(size_t) * (an->nflows + 1));
    size_t k = 0;
    for (size_t i = 0; i < an->nflows; i++)
        if (!proto || an->flows[i].proto == proto) idx[k++] = i;
    g_an = an;
    qsort(idx, k, sizeof(size_t), cmp_flow);
    *n = k;
    return idx;
}

/* ------------------------------------------------------------ builders */

static chart_opts_t opts(const char *title, const char *sub, value_fmt_t f)
{
    chart_opts_t o = {CW, CHH, title, sub, NULL, NULL, f};
    return o;
}

static void build_timeline(const analysis_t *an, chart_out_t *thr, chart_out_t *pps)
{
    /* merge buckets so that at most 600 points are drawn */
    int n = an->tl_n;
    int g = n > 600 ? (n + 599) / 600 : 1;
    int m = (n + g - 1) / g;
    double bw = an->tl_bucket * g;
    double *x = xcalloc((size_t)m, sizeof(double));
    double *b[TL_COUNT], *p[TL_COUNT];
    for (int s = 0; s < TL_COUNT; s++) {
        b[s] = xcalloc((size_t)m, sizeof(double));
        p[s] = xcalloc((size_t)m, sizeof(double));
        for (int i = 0; i < n; i++) {
            b[s][i / g] += an->tl_bytes[s][i] * 8.0 / bw;
            p[s][i / g] += an->tl_pkts[s][i] / bw;
        }
    }
    for (int i = 0; i < m; i++) x[i] = i * bw;

    char sub[160], bb[32];
    fmt_duration(bw, bb, sizeof bb);
    snprintf(sub, sizeof sub, "Przedział czasowy: %s; oś X - czas od początku przechwytu", bb);
    series_t s[3] = {{"TCP", C_S1, b[TL_TCP]}, {"UDP", C_S2, b[TL_UDP]}, {"Inne", C_S3, b[TL_OTHER]}};
    int ns = 3;
    double other = 0;
    for (int i = 0; i < m; i++) other += b[TL_OTHER][i];
    if (other == 0) ns = 2;

    chart_opts_t o = opts("Przepustowość w czasie", sub, VF_BITRATE);
    thr->cv = chart_line(&o, x, m, s, ns);

    series_t sp[3] = {{"TCP", C_S1, p[TL_TCP]}, {"UDP", C_S2, p[TL_UDP]}, {"Inne", C_S3, p[TL_OTHER]}};
    o = opts("Liczba pakietów na sekundę", sub, VF_PPS);
    pps->cv = chart_line(&o, x, m, sp, ns);

    for (int s2 = 0; s2 < TL_COUNT; s2++) { free(b[s2]); free(p[s2]); }
    free(x);
}

static void build_proto(const analysis_t *an, chart_out_t *out)
{
    static const rgb_t cols[P_COUNT] = {C_S1, C_S2, C_S3, C_S4, C_OTHER};
    double v[P_COUNT];
    for (int i = 0; i < P_COUNT; i++) v[i] = (double)an->proto[i].bytes;
    char tot[32];
    fmt_bytes((double)an->bytes, tot, sizeof tot);
    chart_opts_t o = opts("Udział protokołów w ruchu", "Udział w liczbie bajtów (ramki na łączu)", VF_BYTES);
    out->cv = chart_donut(&o, PROTO_NAMES, v, cols, P_COUNT, tot, "łącznie");
}

static void build_sizes(const analysis_t *an, chart_out_t *out)
{
    double t[SIZE_BINS], u[SIZE_BINS];
    for (int i = 0; i < SIZE_BINS; i++) { t[i] = (double)an->size_hist[0][i]; u[i] = (double)an->size_hist[1][i]; }
    series_t s[2] = {{"TCP", C_S1, t}, {"UDP", C_S2, u}};
    chart_opts_t o = opts("Rozkład rozmiarów pakietów", "Liczba pakietów wg długości ramki [B]", VF_COUNT);
    o.xlabel = "Rozmiar ramki [bajty]";
    out->cv = chart_vbars(&o, SIZE_BIN_LABELS, SIZE_BINS, s, 2, 0);
}

static void build_talkers(const analysis_t *an, int topn, chart_out_t *out)
{
    size_t n;
    size_t *idx = top_hosts(an, &n);
    int k = (int)MIN(n, (size_t)topn);
    char **labels = xcalloc((size_t)k + 1, sizeof(char *));
    double *tx = xcalloc((size_t)k + 1, sizeof(double)), *rx = xcalloc((size_t)k + 1, sizeof(double));
    for (int i = 0; i < k; i++) {
        const host_t *h = &an->hosts[idx[i]];
        labels[i] = xmalloc(64);
        addr_str(&h->a, labels[i], 64);
        tx[i] = (double)h->bytes_tx;
        rx[i] = (double)h->bytes_rx;
    }
    series_t s[2] = {{"Wysłane", C_S1, tx}, {"Odebrane", C_S2, rx}};
    char title[64];
    snprintf(title, sizeof title, "Top %d hostów wg wolumenu", k);
    chart_opts_t o = opts(title, "Bajty wysłane i odebrane przez adres IP", VF_BYTES);
    out->cv = chart_hbars(&o, (const char *const *)labels, k, s, 2);
    for (int i = 0; i < k; i++) free(labels[i]);
    free(labels);
    free(tx);
    free(rx);
    free(idx);
}

static void build_services(const analysis_t *an, int topn, chart_out_t *out)
{
    size_t n;
    size_t *idx = top_services(an, &n);
    int k = (int)MIN(n, (size_t)topn);
    char **labels = xcalloc((size_t)k + 1, sizeof(char *));
    double *t = xcalloc((size_t)k + 1, sizeof(double)), *u = xcalloc((size_t)k + 1, sizeof(double));
    for (int i = 0; i < k; i++) {
        const service_t *s = &an->svcs[idx[i]];
        const char *nm = service_name(s->proto, s->port);
        labels[i] = xmalloc(64);
        snprintf(labels[i], 64, "%s/%u%s%s", s->proto == IPPROTO_TCP_ ? "TCP" : "UDP", s->port, nm ? " " : "",
                 nm ? nm : "");
        if (s->proto == IPPROTO_TCP_) t[i] = (double)s->bytes;
        else u[i] = (double)s->bytes;
    }
    series_t s[2] = {{"TCP", C_S1, t}, {"UDP", C_S2, u}};
    char title[64];
    snprintf(title, sizeof title, "Top %d usług (port serwera)", k);
    chart_opts_t o = opts(title, "Wolumen ruchu przypisany do portu po stronie serwera", VF_BYTES);
    out->cv = chart_hbars(&o, (const char *const *)labels, k, s, 2);
    for (int i = 0; i < k; i++) free(labels[i]);
    free(labels);
    free(t);
    free(u);
    free(idx);
}

static void build_flags(const analysis_t *an, chart_out_t *out)
{
    double v[F_COUNT];
    for (int i = 0; i < F_COUNT; i++) v[i] = (double)an->flag_count[i];
    series_t s = {"Pakiety", C_S1, v};
    chart_opts_t o = opts("Flagi TCP", "Liczba segmentów TCP z ustawioną flagą", VF_COUNT);
    out->cv = chart_vbars(&o, FLAG_NAMES, F_COUNT, &s, 1, 0);
}

static void build_states(const analysis_t *an, chart_out_t *out)
{
    double v[TCS_COUNT];
    for (int i = 0; i < TCS_COUNT; i++) v[i] = (double)an->tcs_count[i];
    series_t s = {"Połączenia", C_S1, v};
    chart_opts_t o = opts("Stan połączeń TCP", "Klasyfikacja połączeń na koniec przechwytu", VF_COUNT);
    out->cv = chart_hbars(&o, TCS_NAMES, TCS_COUNT, &s, 1);
}

static void build_rtt(const analysis_t *an, chart_out_t *out)
{
    double v[RTT_BINS] = {0};
    for (size_t i = 0; i < an->nflows; i++)
        if (an->flows[i].rtt >= 0) v[rtt_bin(an->flows[i].rtt * 1000.0)]++;
    series_t s = {"Połączenia", C_S1, v};
    chart_opts_t o = opts("Czas nawiązania połączenia TCP (RTT)", "Opóźnienie SYN -> SYN/ACK widziane w punkcie przechwytu", VF_COUNT);
    o.xlabel = "RTT [ms]";
    out->cv = chart_vbars(&o, RTT_BIN_LABELS, RTT_BINS, &s, 1, 0);
}

static void build_anomalies(const anomaly_list_t *al, chart_out_t *out)
{
    double cnt[SEV_COUNT][AC_COUNT];
    memset(cnt, 0, sizeof cnt);
    int used[AC_COUNT] = {0};
    for (size_t i = 0; i < al->n; i++) {
        cnt[al->v[i].sev][al->v[i].cat]++;
        used[al->v[i].cat] = 1;
    }
    const char *cats[AC_COUNT];
    double v[SEV_COUNT][AC_COUNT];
    int k = 0;
    for (int c = 0; c < AC_COUNT; c++) {
        if (!used[c]) continue;
        cats[k] = AC_NAMES[c];
        for (int s = 0; s < SEV_COUNT; s++) v[s][k] = cnt[s][c];
        k++;
    }
    /* series order: most severe first so the legend reads by priority */
    series_t s[SEV_COUNT];
    for (int i = 0; i < SEV_COUNT; i++) {
        int sev = SEV_HIGH - i;
        s[i].name = SEV_NAMES[sev];
        s[i].color = severity_color(sev);
        s[i].v = v[sev];
    }
    chart_opts_t o = opts("Wykryte nieprawidłowości", al->n ? "Liczba zdarzeń wg kategorii i poziomu ważności"
                                                             : "Nie wykryto nieprawidłowości", VF_COUNT);
    out->cv = chart_hbars(&o, cats, k, s, SEV_COUNT);
}

void charts_build(const analysis_t *an, const anomaly_list_t *al, int topn, chart_out_t out[CH_COUNT])
{
    static const char *files[CH_COUNT] = {
        "01_przepustowosc.png", "02_pakiety_na_sekunde.png", "03_protokoly.png", "04_rozmiary_pakietow.png",
        "05_top_hosty.png", "06_top_uslugi.png", "07_flagi_tcp.png", "08_stany_tcp.png", "09_rtt_tcp.png",
        "10_anomalie.png"};
    static const char *caps[CH_COUNT] = {
        "Przepustowość (bit/s) w czasie z podziałem na protokoły",
        "Natężenie ruchu w pakietach na sekundę",
        "Udział protokołów warstwy transportowej w wolumenie",
        "Histogram długości ramek dla TCP i UDP",
        "Hosty generujące największy wolumen",
        "Usługi (port serwera) z największym wolumenem",
        "Rozkład flag TCP",
        "Klasyfikacja stanów połączeń TCP",
        "Histogram czasu SYN -> SYN/ACK",
        "Wykryte nieprawidłowości wg kategorii"};
    for (int i = 0; i < CH_COUNT; i++) {
        out[i].file = files[i];
        out[i].caption = caps[i];
        out[i].cv = NULL;
        out[i].pdf_img = -1;
    }
    build_timeline(an, &out[CH_THROUGHPUT], &out[CH_PPS]);
    build_proto(an, &out[CH_PROTO]);
    build_sizes(an, &out[CH_SIZES]);
    build_talkers(an, topn, &out[CH_TALKERS]);
    build_services(an, topn, &out[CH_SERVICES]);
    build_flags(an, &out[CH_FLAGS]);
    build_states(an, &out[CH_TCPSTATES]);
    build_rtt(an, &out[CH_RTT]);
    build_anomalies(al, &out[CH_ANOMALIES]);
}

int charts_write(chart_out_t out[CH_COUNT], const char *dir)
{
    int fails = 0;
    for (int i = 0; i < CH_COUNT; i++) {
        if (!out[i].cv) continue;
        char path[4096];
        snprintf(path, sizeof path, "%s/%s", dir, out[i].file);
        if (png_write(path, out[i].cv) != 0) {
            log_warn("nie można zapisać %s", path);
            fails++;
        }
    }
    return fails;
}

void charts_free(chart_out_t out[CH_COUNT])
{
    for (int i = 0; i < CH_COUNT; i++) { cv_free(out[i].cv); out[i].cv = NULL; }
}
