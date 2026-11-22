#include "report.h"
#include "chart.h"
#include "pdf.h"
#include "pcap_reader.h"

#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ layout */

#define PW PDF_A4_W
#define PH PDF_A4_H
#define ML 48.0
#define MR 48.0
#define MT 58.0
#define MB 54.0
#define CWD (PW - ML - MR)

#define K_INK    0x0B0B0Bu
#define K_INK2   0x52514Eu
#define K_MUTED  0x898781u
#define K_RULE   0xE1E0D9u
#define K_HEAD   0xEFEEEAu
#define K_ZEBRA  0xF8F8F6u
#define K_TILE   0xF4F3EFu
#define K_ACCENT 0x2A78D6u

#define MAX_SECTIONS 12

typedef struct {
    pdf_t      *pdf;
    double      y;
    int         nsec;
    const char *sec_title[MAX_SECTIONS];
    int         sec_page[MAX_SECTIONS];
    double      toc_y;
    int         toc_page;
} rep_t;

static void page_header(rep_t *r)
{
    int pg = pdf_page_count(r->pdf);
    if (pg > 1) {
        pdf_text(r->pdf, ML, 34, PDF_REG, 8, K_MUTED, "Raport analizy ruchu sieciowego TCP/UDP");
        pdf_line(r->pdf, ML, 40, PW - MR, 40, 0.5, K_RULE);
    }
    r->y = MT;
}

static void new_page(rep_t *r)
{
    pdf_page_new(r->pdf);
    page_header(r);
}

static void ensure(rep_t *r, double h)
{
    if (r->y + h > PH - MB) new_page(r);
}

static void space(rep_t *r, double h) { r->y += h; }

/* truncates s so that it fits in maxw */
static void fit(const char *s, pdf_font_t f, double size, double maxw, char *out, size_t len)
{
    snprintf(out, len, "%s", s);
    if (pdf_text_width(f, size, out) <= maxw) return;
    size_t n = strlen(out);
    while (n > 0) {
        /* step back one UTF-8 code point */
        n--;
        while (n > 0 && ((unsigned char)out[n] & 0xC0) == 0x80) n--;
        if (n + 4 >= len) continue;
        memcpy(out + n, "...", 4);
        if (pdf_text_width(f, size, out) <= maxw) return;
    }
}

/* word-wrapped paragraph starting at x = ML + indent */
static void para_ex(rep_t *r, const char *txt, pdf_font_t f, double size, rgb_t col, double indent, double lh_mul)
{
    double lh = size * lh_mul;
    double maxw = CWD - indent;
    char line[2048] = "";
    size_t ll = 0;
    const char *p = txt;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *ws = p;
        while (*p && *p != ' ') p++;
        size_t wl = (size_t)(p - ws);
        if (wl > 1000) wl = 1000;
        char cand[2048];
        snprintf(cand, sizeof cand, "%s%s%.*s", line, ll ? " " : "", (int)wl, ws);
        if (pdf_text_width(f, size, cand) <= maxw || ll == 0) {
            /* very long single word: hard-break it */
            if (ll == 0 && pdf_text_width(f, size, cand) > maxw) {
                size_t take = wl;
                char part[2048];
                while (take > 1) {
                    snprintf(part, sizeof part, "%.*s", (int)take, ws);
                    if (pdf_text_width(f, size, part) <= maxw) break;
                    take--;
                }
                while (take > 1 && ((unsigned char)ws[take] & 0xC0) == 0x80) take--;
                ensure(r, lh);
                snprintf(part, sizeof part, "%.*s", (int)take, ws);
                pdf_text(r->pdf, ML + indent, r->y + size, f, size, col, part);
                r->y += lh;
                p = ws + take;
                line[0] = 0;
                ll = 0;
                continue;
            }
            snprintf(line, sizeof line, "%s", cand);
            ll = strlen(line);
        } else {
            ensure(r, lh);
            pdf_text(r->pdf, ML + indent, r->y + size, f, size, col, line);
            r->y += lh;
            snprintf(line, sizeof line, "%.*s", (int)wl, ws);
            ll = strlen(line);
        }
    }
    if (ll) {
        ensure(r, lh);
        pdf_text(r->pdf, ML + indent, r->y + size, f, size, col, line);
        r->y += lh;
    }
}

static void para(rep_t *r, const char *txt) { para_ex(r, txt, PDF_REG, 9.5, K_INK2, 0, 1.45); space(r, 4); }

static void bullet(rep_t *r, const char *txt)
{
    ensure(r, 14);
    pdf_rect(r->pdf, ML + 3, r->y + 4.6, 4, 4, K_ACCENT);
    para_ex(r, txt, PDF_REG, 9.5, K_INK2, 14, 1.45);
    space(r, 2);
}

static void h1(rep_t *r, const char *title)
{
    new_page(r);
    if (r->nsec < MAX_SECTIONS) {
        r->sec_title[r->nsec] = title;
        r->sec_page[r->nsec] = pdf_page_count(r->pdf) - 1;
        r->nsec++;
    }
    char num[256];
    snprintf(num, sizeof num, "%d. %s", r->nsec, title);
    pdf_text(r->pdf, ML, r->y + 18, PDF_BOLD, 18, K_INK, num);
    r->y += 26;
    pdf_rect(r->pdf, ML, r->y, 40, 2.5, K_ACCENT);
    r->y += 16;
}

static void h2(rep_t *r, const char *title)
{
    ensure(r, 40);
    space(r, 6);
    pdf_text(r->pdf, ML, r->y + 12, PDF_BOLD, 12, K_INK, title);
    r->y += 20;
}

/* ------------------------------------------------------------------ tables */

typedef struct {
    const char *title;
    double      w;      /* fraction of content width */
    int         right;  /* right aligned */
} col_t;

static void table_header(rep_t *r, const col_t *c, int nc, double rh)
{
    pdf_rect(r->pdf, ML, r->y, CWD, rh, K_HEAD);
    double x = ML;
    char buf[256];
    for (int i = 0; i < nc; i++) {
        double cw = c[i].w * CWD;
        fit(c[i].title, PDF_BOLD, 8, cw - 8, buf, sizeof buf);
        double tx = c[i].right ? x + cw - 4 - pdf_text_width(PDF_BOLD, 8, buf) : x + 4;
        pdf_text(r->pdf, tx, r->y + rh - 4.6, PDF_BOLD, 8, K_INK, buf);
        x += cw;
    }
    r->y += rh;
}

/* cells: nrows * nc strings, row-major */
static void table(rep_t *r, const col_t *c, int nc, char **cells, int nrows)
{
    const double rh = 14.5;
    ensure(r, rh * (nrows > 0 ? 3 : 2));
    table_header(r, c, nc, rh);
    char buf[512];
    for (int row = 0; row < nrows; row++) {
        if (r->y + rh > PH - MB) {
            new_page(r);
            table_header(r, c, nc, rh);
        }
        if (row % 2 == 1) pdf_rect(r->pdf, ML, r->y, CWD, rh, K_ZEBRA);
        double x = ML;
        for (int i = 0; i < nc; i++) {
            double cw = c[i].w * CWD;
            const char *s = cells[row * nc + i] ? cells[row * nc + i] : "";
            fit(s, PDF_REG, 8, cw - 8, buf, sizeof buf);
            double tx = c[i].right ? x + cw - 4 - pdf_text_width(PDF_REG, 8, buf) : x + 4;
            pdf_text(r->pdf, tx, r->y + rh - 4.6, PDF_REG, 8, K_INK2, buf);
            x += cw;
        }
        r->y += rh;
    }
    if (nrows == 0) {
        pdf_text(r->pdf, ML + 4, r->y + rh - 4.6, PDF_REG, 8, K_MUTED, "brak danych");
        r->y += rh;
    }
    pdf_line(r->pdf, ML, r->y, ML + CWD, r->y, 0.6, K_RULE);
    r->y += 10;
}

/* cell storage helper */
typedef struct {
    char **v;
    int    n, cap;
} cells_t;

static void cell(cells_t *c, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;
static void cell(cells_t *c, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    VEC_RESERVE(c->v, c->cap, c->n + 1);
    c->v[c->n++] = xstrdup(buf);
}

static void cells_free(cells_t *c)
{
    for (int i = 0; i < c->n; i++) free(c->v[i]);
    free(c->v);
    c->v = NULL;
    c->n = c->cap = 0;
}

/* key/value two-column table */
static void kv_table(rep_t *r, cells_t *kv)
{
    static const col_t cols[2] = {{"Parametr", 0.55, 0}, {"Wartość", 0.45, 1}};
    table(r, cols, 2, kv->v, kv->n / 2);
    cells_free(kv);
}

/* ------------------------------------------------------------------ widgets */

static void tiles(rep_t *r, const char *const *labels, const char *const *values, int n)
{
    const int per_row = 4;
    const double gap = 8, th = 50;
    double tw = (CWD - gap * (per_row - 1)) / per_row;
    for (int i = 0; i < n; i += per_row) {
        ensure(r, th + gap);
        for (int k = 0; k < per_row && i + k < n; k++) {
            double x = ML + k * (tw + gap);
            pdf_rect(r->pdf, x, r->y, tw, th, K_TILE);
            pdf_text(r->pdf, x + 9, r->y + 15, PDF_REG, 7.5, K_INK2, labels[i + k]);
            char buf[128];
            fit(values[i + k], PDF_BOLD, 14, tw - 16, buf, sizeof buf);
            pdf_text(r->pdf, x + 9, r->y + 38, PDF_BOLD, 14, K_INK, buf);
        }
        r->y += th + gap;
    }
}

static void figure(rep_t *r, const chart_out_t *ch)
{
    if (!ch->cv || ch->pdf_img < 0) return;
    double w = CWD;
    double h = w * ch->cv->h / ch->cv->w;
    ensure(r, h + 22);
    pdf_rect_stroke(r->pdf, ML, r->y, w, h, 0.5, K_RULE);
    pdf_image_draw(r->pdf, ch->pdf_img, ML, r->y, w, h);
    r->y += h + 4;
    char cap[256];
    /* "Rys. NN" taken from the numeric file prefix */
    snprintf(cap, sizeof cap, "Rys. %.2s. %s  [%s]", ch->file, ch->caption, ch->file);
    pdf_text(r->pdf, ML, r->y + 8, PDF_REG, 7.5, K_MUTED, cap);
    r->y += 18;
}

static double badge(rep_t *r, double x, double y, int sev)
{
    const char *t = SEV_NAMES[sev];
    double w = pdf_text_width(PDF_BOLD, 7, t) + 10;
    rgb_t bg = severity_color(sev);
    rgb_t fg = sev == SEV_LOW ? K_INK : 0xFFFFFFu;
    pdf_rect(r->pdf, x, y, w, 12, bg);
    pdf_text(r->pdf, x + 5, y + 8.8, PDF_BOLD, 7, fg, t);
    return w;
}

/* ------------------------------------------------------------------ stats helpers */

static int cmp_dbl(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

typedef struct {
    int    n;
    double min, max, mean, median, p95;
} dstats_t;

static dstats_t rtt_stats(const analysis_t *an)
{
    dstats_t s = {0};
    double *v = xmalloc(sizeof(double) * (an->nflows + 1));
    for (size_t i = 0; i < an->nflows; i++)
        if (an->flows[i].rtt >= 0) v[s.n++] = an->flows[i].rtt * 1000.0;
    if (s.n) {
        qsort(v, (size_t)s.n, sizeof(double), cmp_dbl);
        double sum = 0;
        for (int i = 0; i < s.n; i++) sum += v[i];
        s.min = v[0];
        s.max = v[s.n - 1];
        s.mean = sum / s.n;
        s.median = s.n % 2 ? v[s.n / 2] : (v[s.n / 2 - 1] + v[s.n / 2]) / 2;
        s.p95 = v[(int)floor(0.95 * (s.n - 1))];
    }
    free(v);
    return s;
}

static double pct(uint64_t a, uint64_t b) { return b ? 100.0 * (double)a / (double)b : 0.0; }

static void peak_rate(const analysis_t *an, double *bps, double *at)
{
    *bps = 0;
    *at = 0;
    for (int i = 0; i < an->tl_n; i++) {
        double b = 0;
        for (int s = 0; s < TL_COUNT; s++) b += an->tl_bytes[s][i];
        b = b * 8.0 / an->tl_bucket;
        if (b > *bps) { *bps = b; *at = i * an->tl_bucket; }
    }
}

static const char *ep(const addr_t *a, uint16_t port, char *buf, size_t len)
{
    char s[64];
    addr_str(a, s, sizeof s);
    if (a->ver == 6) snprintf(buf, len, "[%s]:%u", s, port);
    else snprintf(buf, len, "%s:%u", s, port);
    return buf;
}

static const char *basename_of(const char *p)
{
    const char *b = p;
    for (const char *s = p; *s; s++)
        if (*s == '/' || *s == '\\') b = s + 1;
    return b;
}

/* ------------------------------------------------------------------ sections */

static void section_cover(rep_t *r, const report_input_t *in)
{
    const analysis_t *an = in->an;
    const anomaly_list_t *al = in->al;
    char b1[64], b2[64], b3[64], b4[64];

    new_page(r);
    pdf_rect(r->pdf, 0, 0, PW, 6, K_ACCENT);
    pdf_text(r->pdf, ML, 92, PDF_BOLD, 24, K_INK, "Raport analizy ruchu sieciowego");
    pdf_text(r->pdf, ML, 116, PDF_REG, 13, K_INK2, "Komunikacja TCP i UDP na podstawie plików przechwytu pakietów");
    r->y = 136;

    /* meta */
    char line[1024];
    size_t o = 0;
    line[0] = 0;
    for (int i = 0; i < an->nfiles && o < sizeof line - 80; i++)
        o += (size_t)snprintf(line + o, sizeof line - o, "%s%s", i ? ", " : "", basename_of(an->files[i].path));
    char meta[1200];
    snprintf(meta, sizeof meta, "Analizowane pliki: %s", line);
    para_ex(r, meta, PDF_REG, 9, K_INK2, 0, 1.4);
    time_t now = time(NULL);
    fmt_time((double)now, b1, sizeof b1);
    { char *dot = strchr(b1, '.'); if (dot) *dot = 0; }
    if (an->packets && an->first_ts > 0) {
        fmt_time(an->first_ts, b2, sizeof b2);
        fmt_time(an->last_ts, b3, sizeof b3);
        snprintf(meta, sizeof meta, "Okres przechwytu (UTC): %s - %s", b2, b3);
        para_ex(r, meta, PDF_REG, 9, K_INK2, 0, 1.4);
    }
    snprintf(meta, sizeof meta, "Wygenerowano: %s UTC przez %s %s", b1, TOOL_NAME, TOOL_VERSION);
    para_ex(r, meta, PDF_REG, 9, K_INK2, 0, 1.4);
    space(r, 14);

    /* tiles */
    double dur = an->last_ts - an->first_ts;
    int nh = 0, nm = 0, nl = 0;
    for (size_t i = 0; i < al->n; i++) {
        if (al->v[i].sev == SEV_HIGH) nh++;
        else if (al->v[i].sev == SEV_MEDIUM) nm++;
        else if (al->v[i].sev == SEV_LOW) nl++;
    }
    char v[8][64];
    fmt_int(an->packets, v[0], sizeof v[0]);
    fmt_bytes((double)an->bytes, v[1], sizeof v[1]);
    fmt_duration(dur, v[2], sizeof v[2]);
    fmt_bitrate(dur > 0 ? (double)an->bytes * 8.0 / dur : 0, v[3], sizeof v[3]);
    fmt_int(an->tcp_flows, v[4], sizeof v[4]);
    fmt_int(an->udp_flows, v[5], sizeof v[5]);
    fmt_int(an->nhosts, v[6], sizeof v[6]);
    snprintf(v[7], sizeof v[7], "%zu (%d wys.)", al->n, nh);
    const char *labels[8] = {"Pakiety", "Wolumen", "Czas trwania", "Średnia przepustowość",
                             "Połączenia TCP", "Przepływy UDP", "Adresy IP", "Nieprawidłowości"};
    const char *vals[8] = {v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]};
    tiles(r, labels, vals, 8);
    space(r, 10);

    /* key findings */
    h2(r, "Najważniejsze wnioski");
    char t[1024];
    double pk, pkat;
    peak_rate(an, &pk, &pkat);
    if (!an->packets) {
        bullet(r, "Pliki wejściowe nie zawierały żadnych pakietów - brak danych do analizy.");
    } else {
        snprintf(t, sizeof t, "Przeanalizowano %s pakietów (%s) z okresu %s. Średnia przepustowość %s, "
                              "szczytowa %s (około %.0f s od początku przechwytu).",
                 v[0], v[1], v[2], v[3], fmt_bitrate(pk, b1, sizeof b1), pkat);
        bullet(r, t);
        snprintf(t, sizeof t, "Struktura ruchu: TCP %.1f%%, UDP %.1f%%, ICMP %.1f%%, pozostałe %.1f%% wolumenu; "
                              "IPv4 %.1f%% / IPv6 %.1f%% pakietów.",
                 pct(an->proto[P_TCP].bytes, an->bytes), pct(an->proto[P_UDP].bytes, an->bytes),
                 pct(an->proto[P_ICMP].bytes, an->bytes),
                 pct(an->proto[P_OTHER_IP].bytes + an->proto[P_NON_IP].bytes, an->bytes),
                 pct(an->ipv4.pkts, an->packets), pct(an->ipv6.pkts, an->packets));
        bullet(r, t);
        size_t nhst;
        size_t *hi = top_hosts(an, &nhst);
        if (nhst) {
            const host_t *h = &an->hosts[hi[0]];
            addr_str(&h->a, b2, sizeof b2);
            snprintf(t, sizeof t, "Najaktywniejszy host: %s - %s wysłanych i %s odebranych.", b2,
                     fmt_bytes((double)h->bytes_tx, b3, sizeof b3), fmt_bytes((double)h->bytes_rx, b4, sizeof b4));
            bullet(r, t);
        }
        free(hi);
        size_t nsv;
        size_t *si = top_services(an, &nsv);
        if (nsv) {
            const service_t *s = &an->svcs[si[0]];
            const char *sn = service_name(s->proto, s->port);
            snprintf(t, sizeof t, "Największy wolumen generuje usługa %s/%u%s%s%s: %s w %u przepływach.",
                     s->proto == IPPROTO_TCP_ ? "TCP" : "UDP", s->port, sn ? " (" : "", sn ? sn : "", sn ? ")" : "",
                     fmt_bytes((double)s->bytes, b3, sizeof b3), s->flows);
            bullet(r, t);
        }
        free(si);
        if (an->tcp_flows) {
            uint64_t failed = an->tcs_count[TCS_REJECTED] + an->tcs_count[TCS_NO_REPLY] + an->tcs_count[TCS_HALF_OPEN];
            dstats_t rs = rtt_stats(an);
            snprintf(t, sizeof t, "TCP: %llu połączeń, %.1f%% nieudanych prób nawiązania, retransmisje %.2f%% "
                                  "segmentów z danymi%s%s.",
                     (unsigned long long)an->tcp_flows, pct(failed, an->tcp_flows),
                     pct(an->tcp_retrans, an->tcp_data_segs), rs.n ? ", mediana RTT " : "",
                     rs.n ? (snprintf(b4, sizeof b4, "%.2f ms", rs.median), b4) : "");
            bullet(r, t);
        }
        if (al->n) {
            snprintf(t, sizeof t, "Wykryto %zu nieprawidłowości: %d o wysokim, %d o średnim i %d o niskim "
                                  "poziomie ważności (szczegóły w rozdziale 6).",
                     al->n, nh, nm, nl);
            bullet(r, t);
            int shown = 0;
            for (size_t i = 0; i < al->n && shown < 4; i++) {
                if (al->v[i].sev < SEV_MEDIUM) continue;
                snprintf(t, sizeof t, "[%s] %s", SEV_NAMES[al->v[i].sev], al->v[i].title);
                para_ex(r, t, PDF_BOLD, 8.5, K_INK, 22, 1.45);
                shown++;
            }
            space(r, 3);
        } else {
            bullet(r, "Nie wykryto nieprawidłowości przekraczających progi detekcji.");
        }
    }

    /* reserve the table of contents */
    space(r, 6);
    ensure(r, 150);
    h2(r, "Spis treści");
    r->toc_page = pdf_page_count(r->pdf) - 1;
    r->toc_y = r->y;
}

static void draw_toc(rep_t *r)
{
    pdf_set_page(r->pdf, r->toc_page);
    double y = r->toc_y;
    for (int i = 0; i < r->nsec; i++) {
        char t[256], p[16];
        snprintf(t, sizeof t, "%d.  %s", i + 1, r->sec_title[i]);
        snprintf(p, sizeof p, "%d", r->sec_page[i] + 1);
        pdf_text(r->pdf, ML, y + 10, PDF_REG, 10, K_INK, t);
        double tw = pdf_text_width(PDF_REG, 10, t);
        double pw = pdf_text_width(PDF_REG, 10, p);
        /* dotted leader */
        for (double x = ML + tw + 6; x < PW - MR - pw - 6; x += 4) pdf_rect(r->pdf, x, y + 9, 0.8, 0.8, K_MUTED);
        pdf_text(r->pdf, PW - MR - pw, y + 10, PDF_REG, 10, K_INK, p);
        pdf_link(r->pdf, ML, y, CWD, 14, r->sec_page[i]);
        y += 16;
    }
}

static void draw_footers(rep_t *r, const analysis_t *an)
{
    int n = pdf_page_count(r->pdf);
    const char *src = an->nfiles ? basename_of(an->files[0].path) : "";
    for (int i = 0; i < n; i++) {
        pdf_set_page(r->pdf, i);
        pdf_line(r->pdf, ML, PH - 38, PW - MR, PH - 38, 0.5, K_RULE);
        char t[300];
        snprintf(t, sizeof t, "%s %s  -  %s%s", TOOL_NAME, TOOL_VERSION, src, an->nfiles > 1 ? " (+ inne)" : "");
        pdf_text(r->pdf, ML, PH - 26, PDF_REG, 7.5, K_MUTED, t);
        snprintf(t, sizeof t, "Strona %d z %d", i + 1, n);
        pdf_text(r->pdf, PW - MR - pdf_text_width(PDF_REG, 7.5, t), PH - 26, PDF_REG, 7.5, K_MUTED, t);
    }
}

static void section_capture(rep_t *r, const report_input_t *in)
{
    const analysis_t *an = in->an;
    char b1[64], b2[64];
    h1(r, "Informacje o przechwycie");
    para(r, "Zestawienie plików wejściowych i podstawowych parametrów przechwytu. Narzędzie samodzielnie "
            "odczytuje formaty pcap (mikro- i nanosekundowy, oba porządki bajtów) oraz pcapng; "
            "dekoduje warstwy Ethernet (z VLAN 802.1Q/QinQ), Linux SLL/SLL2, loopback i surowe IP.");

    static const col_t fc[6] = {{"Plik", 0.30, 0}, {"Format", 0.10, 0}, {"Warstwa łącza", 0.20, 0},
                                {"Pakiety", 0.12, 1}, {"Bajty", 0.12, 1}, {"Uwagi", 0.16, 0}};
    cells_t c = {0};
    for (int i = 0; i < an->nfiles; i++) {
        const file_info_t *f = &an->files[i];
        cell(&c, "%s", basename_of(f->path));
        cell(&c, "%s", f->error && !f->packets ? "-" : f->is_ng ? "pcapng" : "pcap");
        cell(&c, "%s", f->linktype >= 0 ? pr_linktype_name(f->linktype) : "-");
        cell(&c, "%s", fmt_int(f->packets, b1, sizeof b1));
        cell(&c, "%s", fmt_bytes((double)f->bytes, b2, sizeof b2));
        cell(&c, "%s", f->error ? f->errmsg : f->truncated_records ? "obcięty koniec pliku" : "OK");
    }
    table(r, fc, 6, c.v, an->nfiles);
    cells_free(&c);

    h2(r, "Parametry przechwytu");
    cells_t kv = {0};
    double dur = an->last_ts - an->first_ts;
    cell(&kv, "Początek przechwytu (UTC)"); cell(&kv, "%s", an->first_ts > 0 ? fmt_time(an->first_ts, b1, sizeof b1) : "-");
    cell(&kv, "Koniec przechwytu (UTC)"); cell(&kv, "%s", an->last_ts > 0 ? fmt_time(an->last_ts, b1, sizeof b1) : "-");
    cell(&kv, "Czas trwania"); cell(&kv, "%s", fmt_duration(dur, b1, sizeof b1));
    cell(&kv, "Liczba pakietów"); cell(&kv, "%s", fmt_int(an->packets, b1, sizeof b1));
    cell(&kv, "Wolumen (długość ramek na łączu)"); cell(&kv, "%s", fmt_bytes((double)an->bytes, b1, sizeof b1));
    cell(&kv, "Wolumen zapisany w pliku"); cell(&kv, "%s", fmt_bytes((double)an->cap_bytes, b1, sizeof b1));
    cell(&kv, "Średnie tempo pakietów"); cell(&kv, "%.1f pkt/s", dur > 0 ? an->packets / dur : 0.0);
    cell(&kv, "Rozmiar ramki min / śr. / maks.");
    cell(&kv, "%u / %.0f / %u B", an->packets ? an->min_len : 0, an->packets ? (double)an->bytes / an->packets : 0.0, an->max_len);
    cell(&kv, "Pakiety IPv4 / IPv6");
    cell(&kv, "%llu / %llu", (unsigned long long)an->ipv4.pkts, (unsigned long long)an->ipv6.pkts);
    cell(&kv, "Ramki nie-IP (w tym ARP)");
    cell(&kv, "%llu (%llu)", (unsigned long long)an->proto[P_NON_IP].pkts, (unsigned long long)an->arp);
    cell(&kv, "Fragmenty IP"); cell(&kv, "%llu", (unsigned long long)an->fragments);
    cell(&kv, "Pakiety obcięte / uszkodzone");
    cell(&kv, "%llu / %llu", (unsigned long long)an->truncated, (unsigned long long)an->malformed);
    kv_table(r, &kv);
}

static void section_traffic(rep_t *r, const report_input_t *in)
{
    const analysis_t *an = in->an;
    char b1[64], b2[64];
    h1(r, "Statystyki ruchu");
    para(r, "Rozkład ruchu na protokoły warstwy transportowej. Wolumen liczony jest jako długość ramki na łączu "
            "(pole orig_len), więc nie zależy od ustawionego snaplen.");

    static const col_t pc[6] = {{"Protokół", 0.22, 0}, {"Pakiety", 0.16, 1}, {"% pakietów", 0.14, 1},
                                {"Bajty", 0.18, 1}, {"% bajtów", 0.14, 1}, {"Śr. ramka", 0.16, 1}};
    cells_t c = {0};
    for (int i = 0; i < P_COUNT; i++) {
        cell(&c, "%s", PROTO_NAMES[i]);
        cell(&c, "%s", fmt_int(an->proto[i].pkts, b1, sizeof b1));
        cell(&c, "%.2f%%", pct(an->proto[i].pkts, an->packets));
        cell(&c, "%s", fmt_bytes((double)an->proto[i].bytes, b2, sizeof b2));
        cell(&c, "%.2f%%", pct(an->proto[i].bytes, an->bytes));
        cell(&c, "%.0f B", an->proto[i].pkts ? (double)an->proto[i].bytes / an->proto[i].pkts : 0.0);
    }
    table(r, pc, 6, c.v, P_COUNT);
    cells_free(&c);

    figure(r, &in->charts[CH_THROUGHPUT]);
    double pk, at;
    peak_rate(an, &pk, &at);
    char t[512];
    snprintf(t, sizeof t, "Szczytowa przepustowość w pojedynczym przedziale: %s (t = %.1f s). Rozdzielczość osi "
                          "czasu: %s.",
             fmt_bitrate(pk, b1, sizeof b1), at, fmt_duration(an->tl_bucket, b2, sizeof b2));
    para(r, t);
    figure(r, &in->charts[CH_PPS]);
    figure(r, &in->charts[CH_PROTO]);
    figure(r, &in->charts[CH_SIZES]);

    h2(r, "Rozkład rozmiarów ramek");
    static const col_t sc[5] = {{"Rozmiar ramki [B]", 0.28, 0}, {"TCP", 0.18, 1}, {"% TCP", 0.18, 1},
                                {"UDP", 0.18, 1}, {"% UDP", 0.18, 1}};
    uint64_t tt = 0, tu = 0;
    for (int i = 0; i < SIZE_BINS; i++) { tt += an->size_hist[0][i]; tu += an->size_hist[1][i]; }
    for (int i = 0; i < SIZE_BINS; i++) {
        cell(&c, "%s", SIZE_BIN_LABELS[i]);
        cell(&c, "%llu", (unsigned long long)an->size_hist[0][i]);
        cell(&c, "%.1f%%", pct(an->size_hist[0][i], tt));
        cell(&c, "%llu", (unsigned long long)an->size_hist[1][i]);
        cell(&c, "%.1f%%", pct(an->size_hist[1][i], tu));
    }
    table(r, sc, 5, c.v, SIZE_BINS);
    cells_free(&c);
}

static void section_hosts(rep_t *r, const report_input_t *in)
{
    const analysis_t *an = in->an;
    char b1[64], b2[64], b3[64];
    h1(r, "Hosty i usługi");
    para(r, "Najaktywniejsze adresy IP oraz usługi. Usługa to para (protokół, port serwera); serwer jest "
            "ustalany na podstawie kierunku pakietu SYN (TCP) albo - gdy go brak - portu dobrze znanego.");
    figure(r, &in->charts[CH_TALKERS]);

    static const col_t hc[7] = {{"Adres IP", 0.27, 0}, {"Typ", 0.10, 0}, {"Wysłane", 0.13, 1},
                                {"Odebrane", 0.13, 1}, {"Pakiety", 0.13, 1}, {"Poł. jako klient", 0.12, 1},
                                {"jako serwer", 0.12, 1}};
    size_t n;
    size_t *idx = top_hosts(an, &n);
    int k = (int)MIN(n, (size_t)in->topn * 2);
    cells_t c = {0};
    for (int i = 0; i < k; i++) {
        const host_t *h = &an->hosts[idx[i]];
        cell(&c, "%s", addr_str(&h->a, b1, sizeof b1));
        cell(&c, "%s", addr_is_multicast(&h->a) ? "multicast" : addr_is_private(&h->a) ? "prywatny" : "publiczny");
        cell(&c, "%s", fmt_bytes((double)h->bytes_tx, b2, sizeof b2));
        cell(&c, "%s", fmt_bytes((double)h->bytes_rx, b3, sizeof b3));
        cell(&c, "%s", fmt_int(h->pkts_tx + h->pkts_rx, b1, sizeof b1));
        cell(&c, "%u", h->flows_cli);
        cell(&c, "%u", h->flows_srv);
    }
    h2(r, "Najaktywniejsze hosty");
    table(r, hc, 7, c.v, k);
    cells_free(&c);
    free(idx);

    figure(r, &in->charts[CH_SERVICES]);
    static const col_t sc[6] = {{"Protokół/port", 0.18, 0}, {"Usługa", 0.20, 0}, {"Przepływy", 0.14, 1},
                                {"Pakiety", 0.16, 1}, {"Bajty", 0.16, 1}, {"% wolumenu", 0.16, 1}};
    idx = top_services(an, &n);
    k = (int)MIN(n, (size_t)in->topn * 2);
    for (int i = 0; i < k; i++) {
        const service_t *s = &an->svcs[idx[i]];
        const char *nm = service_name(s->proto, s->port);
        cell(&c, "%s/%u", s->proto == IPPROTO_TCP_ ? "TCP" : "UDP", s->port);
        cell(&c, "%s", nm ? nm : "-");
        cell(&c, "%u", s->flows);
        cell(&c, "%s", fmt_int(s->pkts, b1, sizeof b1));
        cell(&c, "%s", fmt_bytes((double)s->bytes, b2, sizeof b2));
        cell(&c, "%.2f%%", pct(s->bytes, an->bytes));
    }
    h2(r, "Najpopularniejsze usługi");
    table(r, sc, 6, c.v, k);
    cells_free(&c);
    free(idx);
}

static void flows_table(rep_t *r, const analysis_t *an, uint8_t proto, int topn)
{
    char b1[96], b2[96], b3[64], b4[64];
    size_t n;
    size_t *idx = top_flows(an, proto, &n);
    int k = (int)MIN(n, (size_t)topn);
    cells_t c = {0};
    if (proto == IPPROTO_TCP_) {
        static const col_t cols[7] = {{"Klient", 0.20, 0}, {"Serwer", 0.20, 0}, {"Pakiety", 0.08, 1},
                                      {"Bajty", 0.10, 1}, {"Czas", 0.10, 1}, {"Retr.", 0.06, 1}, {"Stan", 0.26, 0}};
        for (int i = 0; i < k; i++) {
            const flow_t *f = &an->flows[idx[i]];
            cell(&c, "%s", ep(&f->cli, f->cport, b1, sizeof b1));
            cell(&c, "%s", ep(&f->srv, f->sport, b2, sizeof b2));
            cell(&c, "%llu", (unsigned long long)flow_total_pkts(f));
            cell(&c, "%s", fmt_bytes((double)flow_total_bytes(f), b3, sizeof b3));
            cell(&c, "%s", fmt_duration(f->last - f->first, b4, sizeof b4));
            cell(&c, "%u", f->retrans[0] + f->retrans[1]);
            cell(&c, "%s", TCS_NAMES[f->state]);
        }
        table(r, cols, 7, c.v, k);
    } else {
        static const col_t cols[7] = {{"Klient", 0.23, 0}, {"Serwer", 0.23, 0}, {"Usługa", 0.12, 0},
                                      {"Pak. ->", 0.09, 1}, {"Pak. <-", 0.09, 1}, {"Bajty", 0.12, 1}, {"Czas", 0.12, 1}};
        for (int i = 0; i < k; i++) {
            const flow_t *f = &an->flows[idx[i]];
            const char *nm = service_name(f->proto, f->sport);
            cell(&c, "%s", ep(&f->cli, f->cport, b1, sizeof b1));
            cell(&c, "%s", ep(&f->srv, f->sport, b2, sizeof b2));
            cell(&c, "%s", nm ? nm : "-");
            cell(&c, "%llu", (unsigned long long)f->pkts[0]);
            cell(&c, "%llu", (unsigned long long)f->pkts[1]);
            cell(&c, "%s", fmt_bytes((double)flow_total_bytes(f), b3, sizeof b3));
            cell(&c, "%s", fmt_duration(f->last - f->first, b4, sizeof b4));
        }
        table(r, cols, 7, c.v, k);
    }
    cells_free(&c);
    free(idx);
}

static void section_tcp(rep_t *r, const report_input_t *in)
{
    const analysis_t *an = in->an;
    char b1[64];
    h1(r, "Charakterystyka komunikacji TCP");
    para(r, "Każde połączenie TCP jest śledzone dwukierunkowo. Analizowany jest przebieg uzgadniania "
            "(SYN, SYN/ACK, ACK), zamykanie (FIN/RST), numery sekwencyjne (retransmisje, luki) oraz "
            "ogłaszane okno odbiorcze.");

    dstats_t rs = rtt_stats(an);
    uint64_t failed = an->tcs_count[TCS_REJECTED] + an->tcs_count[TCS_NO_REPLY] + an->tcs_count[TCS_HALF_OPEN];
    cells_t kv = {0};
    cell(&kv, "Liczba połączeń TCP"); cell(&kv, "%s", fmt_int(an->tcp_flows, b1, sizeof b1));
    cell(&kv, "Pakiety / wolumen TCP");
    {
        char b2[64], b3[64];
        cell(&kv, "%s / %s", fmt_int(an->proto[P_TCP].pkts, b2, sizeof b2), fmt_bytes((double)an->proto[P_TCP].bytes, b3, sizeof b3));
    }
    for (int i = 0; i < TCS_COUNT; i++) {
        cell(&kv, "  %s", TCS_NAMES[i]);
        cell(&kv, "%llu (%.1f%%)", (unsigned long long)an->tcs_count[i], pct(an->tcs_count[i], an->tcp_flows));
    }
    cell(&kv, "Nieudane próby połączeń"); cell(&kv, "%llu (%.1f%%)", (unsigned long long)failed, pct(failed, an->tcp_flows));
    cell(&kv, "Segmenty z danymi"); cell(&kv, "%s", fmt_int(an->tcp_data_segs, b1, sizeof b1));
    cell(&kv, "Retransmisje"); cell(&kv, "%llu (%.2f%%)", (unsigned long long)an->tcp_retrans, pct(an->tcp_retrans, an->tcp_data_segs));
    cell(&kv, "Luki w numeracji (utrata przed punktem przechwytu)"); cell(&kv, "%llu", (unsigned long long)an->tcp_ooo);
    cell(&kv, "Ogłoszenia zerowego okna"); cell(&kv, "%llu", (unsigned long long)an->tcp_zero_win);
    cell(&kv, "Pakiety z niedozwolonymi flagami");
    cell(&kv, "%llu", (unsigned long long)(an->bad_flags[0] + an->bad_flags[1] + an->bad_flags[2] + an->bad_flags[3]));
    if (rs.n) {
        cell(&kv, "RTT uzgadniania: próbek"); cell(&kv, "%d", rs.n);
        cell(&kv, "RTT min / mediana / średnia");
        cell(&kv, "%.2f / %.2f / %.2f ms", rs.min, rs.median, rs.mean);
        cell(&kv, "RTT 95. percentyl / maks."); cell(&kv, "%.2f / %.2f ms", rs.p95, rs.max);
    }
    kv_table(r, &kv);

    figure(r, &in->charts[CH_FLAGS]);
    figure(r, &in->charts[CH_TCPSTATES]);
    figure(r, &in->charts[CH_RTT]);
    h2(r, "Największe połączenia TCP");
    flows_table(r, an, IPPROTO_TCP_, in->topn);
}

static void section_udp(rep_t *r, const report_input_t *in)
{
    const analysis_t *an = in->an;
    char b1[64], b2[64];
    h1(r, "Charakterystyka komunikacji UDP");
    para(r, "UDP jest bezpołączeniowy, dlatego przepływ to zbiór datagramów o tej samej piątce (adresy, porty, "
            "protokół) w obu kierunkach, rozdzielany po okresie bezczynności. Przepływy jednokierunkowe bez "
            "odpowiedzi są typowe dla skanowania i ataków wolumetrycznych.");
    uint64_t oneway = 0, pl = 0, pk = 0;
    for (size_t i = 0; i < an->nflows; i++) {
        const flow_t *f = &an->flows[i];
        if (f->proto != IPPROTO_UDP_) continue;
        if (!f->pkts[1]) oneway++;
        pl += f->payload[0] + f->payload[1];
        pk += flow_total_pkts(f);
    }
    cells_t kv = {0};
    cell(&kv, "Liczba przepływów UDP"); cell(&kv, "%s", fmt_int(an->udp_flows, b1, sizeof b1));
    cell(&kv, "Pakiety / wolumen UDP");
    cell(&kv, "%s / %s", fmt_int(an->proto[P_UDP].pkts, b1, sizeof b1), fmt_bytes((double)an->proto[P_UDP].bytes, b2, sizeof b2));
    cell(&kv, "Przepływy jednokierunkowe (bez odpowiedzi)");
    cell(&kv, "%llu (%.1f%%)", (unsigned long long)oneway, pct(oneway, an->udp_flows));
    cell(&kv, "Średni ładunek datagramu"); cell(&kv, "%.0f B", pk ? (double)pl / pk : 0.0);
    cell(&kv, "ICMP: port/host nieosiągalny"); cell(&kv, "%llu", (unsigned long long)an->icmp_unreach);
    cell(&kv, "ICMP: echo request / reply");
    cell(&kv, "%llu / %llu", (unsigned long long)an->icmp_echo_req, (unsigned long long)an->icmp_echo_rep);
    kv_table(r, &kv);

    h2(r, "Największe przepływy UDP");
    flows_table(r, an, IPPROTO_UDP_, in->topn);

    h2(r, "Ruch DNS");
    cell(&kv, "Zapytania / odpowiedzi");
    cell(&kv, "%llu / %llu", (unsigned long long)an->dns_queries, (unsigned long long)an->dns_responses);
    cell(&kv, "NXDOMAIN"); cell(&kv, "%llu (%.1f%% odpowiedzi)", (unsigned long long)an->dns_nxdomain, pct(an->dns_nxdomain, an->dns_responses));
    cell(&kv, "SERVFAIL / inne błędy");
    cell(&kv, "%llu / %llu", (unsigned long long)an->dns_servfail, (unsigned long long)an->dns_other_err);
    cell(&kv, "Unikalne nazwy"); cell(&kv, "%zu", an->ndns);
    cell(&kv, "Niepoprawne komunikaty DNS"); cell(&kv, "%llu", (unsigned long long)an->dns_malformed);
    kv_table(r, &kv);

    if (an->ndns) {
        /* top queried names */
        size_t *idx = xmalloc(sizeof(size_t) * an->ndns);
        for (size_t i = 0; i < an->ndns; i++) idx[i] = i;
        /* simple selection of top N */
        int k = (int)MIN(an->ndns, (size_t)in->topn);
        for (int i = 0; i < k; i++) {
            size_t best = (size_t)i;
            for (size_t j = (size_t)i + 1; j < an->ndns; j++)
                if (an->dns_names[idx[j]].queries > an->dns_names[idx[best]].queries) best = j;
            size_t t = idx[i]; idx[i] = idx[best]; idx[best] = t;
        }
        static const col_t cols[4] = {{"Nazwa", 0.58, 0}, {"Zapytania", 0.14, 1}, {"NXDOMAIN", 0.14, 1},
                                      {"Entropia", 0.14, 1}};
        cells_t c = {0};
        for (int i = 0; i < k; i++) {
            const dns_name_t *d = &an->dns_names[idx[i]];
            cell(&c, "%s", d->name);
            cell(&c, "%u", d->queries);
            cell(&c, "%u", d->nxdomain);
            cell(&c, "%.2f", d->entropy);
        }
        h2(r, "Najczęściej odpytywane nazwy");
        table(r, cols, 4, c.v, k);
        cells_free(&c);
        free(idx);
    }
}

static void section_anomalies(rep_t *r, const report_input_t *in)
{
    const anomaly_list_t *al = in->al;
    h1(r, "Wykryte nieprawidłowości");
    para(r, "Heurystyki wykrywania działają na tablicy przepływów i liczników hostów. Każde zdarzenie ma "
            "poziom ważności: WYSOKI (prawdopodobny atak lub kompromitacja), ŚREDNI (wymaga weryfikacji), "
            "NISKI (problem wydajnościowy lub higiena konfiguracji), INFO (jakość danych). Progi opisano w "
            "rozdziale 7.");
    if (al->n) figure(r, &in->charts[CH_ANOMALIES]);
    else {
        para_ex(r, "Nie wykryto nieprawidłowości przekraczających skonfigurowane progi.", PDF_BOLD, 10, K_INK, 0, 1.5);
        return;
    }

    h2(r, "Zestawienie");
    static const col_t cols[4] = {{"#", 0.06, 1}, {"Ważność", 0.12, 0}, {"Kategoria", 0.22, 0}, {"Opis", 0.60, 0}};
    cells_t c = {0};
    for (size_t i = 0; i < al->n; i++) {
        cell(&c, "%zu", i + 1);
        cell(&c, "%s", SEV_NAMES[al->v[i].sev]);
        cell(&c, "%s", AC_NAMES[al->v[i].cat]);
        cell(&c, "%s", al->v[i].title);
    }
    table(r, cols, 4, c.v, (int)al->n);
    cells_free(&c);

    h2(r, "Szczegóły");
    for (size_t i = 0; i < al->n; i++) {
        const anomaly_t *a = &al->v[i];
        ensure(r, 60);
        double bw = badge(r, ML, r->y, a->sev);
        char cat[96];
        snprintf(cat, sizeof cat, "#%zu  %s", i + 1, AC_NAMES[a->cat]);
        pdf_text(r->pdf, ML + bw + 8, r->y + 9, PDF_REG, 8, K_MUTED, cat);
        r->y += 17;
        para_ex(r, a->title, PDF_BOLD, 10, K_INK, 0, 1.35);
        space(r, 1);
        para_ex(r, a->detail, PDF_REG, 9, K_INK2, 0, 1.4);
        if (a->first > 0 && a->last >= a->first) {
            char t1[48], t2[48], d[48], w[200];
            snprintf(w, sizeof w, "Okno czasowe: %s - %s UTC (%s)", fmt_time(a->first, t1, sizeof t1),
                     fmt_time(a->last, t2, sizeof t2), fmt_duration(a->last - a->first, d, sizeof d));
            para_ex(r, w, PDF_REG, 8, K_MUTED, 0, 1.4);
        }
        space(r, 5);
        pdf_line(r->pdf, ML, r->y, ML + CWD, r->y, 0.4, K_RULE);
        space(r, 8);
    }
}

static void section_method(rep_t *r, const report_input_t *in)
{
    const detect_opts_t *o = in->dopts;
    char t[1024];
    h1(r, "Metodologia i ograniczenia");
    h2(r, "Przetwarzanie danych");
    para(r, "1) Pierwsze przejście po plikach wyznacza zakres czasu, na tej podstawie dobierana jest "
            "rozdzielczość osi czasu (do ok. 300 przedziałów). 2) Drugie przejście dekoduje każdy pakiet: "
            "warstwa łącza -> IPv4/IPv6 (z nagłówkami rozszerzeń) -> TCP/UDP/ICMP, i aktualizuje liczniki "
            "globalne, liczniki hostów, tablicę przepływów (tablica haszująca z kluczem znormalizowanej "
            "piątki) oraz statystyki DNS. 3) Po wczytaniu danych klasyfikowane są stany połączeń TCP, "
            "agregowane usługi i uruchamiane detektory nieprawidłowości.");
    snprintf(t, sizeof t, "Przepływ jest dzielony na nowy po %.0f s bezczynności lub po ponownym SYN na "
                          "zamkniętym połączeniu (ponowne użycie portu).",
             in->aopts->flow_timeout);
    para(r, t);
    para(r, "Retransmisja TCP: segment niosący dane (lub SYN/FIN), którego numer sekwencyjny jest mniejszy niż "
            "oczekiwany następny numer w danym kierunku (z pominięciem pakietów keep-alive). Luka: numer "
            "większy niż oczekiwany, co oznacza utratę pakietu przed punktem przechwytu. RTT mierzone jest "
            "jako czas między ostatnim SYN a SYN/ACK.");
    h2(r, "Heurystyki i progi");
    snprintf(t, sizeof t, "Skanowanie portów: jeden host źródłowy kontaktuje się z >= %d różnymi portami jednego "
                          "celu, a >= 60%% prób to sondy (SYN bez odpowiedzi, SYN->RST, półotwarte, flagi "
                          "FIN/NULL/XMAS, połączenie bez danych). Technika jest określana na podstawie flag.",
             o->scan_ports);
    bullet(r, t);
    snprintf(t, sizeof t, "Skanowanie hostów: jeden host źródłowy sonduje ten sam port na >= %d różnych "
                          "hostach (adresy multicast pomijane).",
             o->sweep_hosts);
    bullet(r, t);
    snprintf(t, sizeof t, "SYN flood: >= %d nieudanych połączeń do jednej usługi stanowiących >= 50%% "
                          "wszystkich połączeń, w tempie >= %.0f SYN/s.",
             o->synflood_min, o->synflood_rate);
    bullet(r, t);
    snprintf(t, sizeof t, "UDP flood: >= %llu datagramów do jednego hosta w tempie >= %.0f pkt/s, przy "
                          "odpowiedziach < 10%% ruchu.",
             (unsigned long long)o->udpflood_min, o->udpflood_pps);
    bullet(r, t);
    bullet(r, "Niedozwolone flagi TCP: NULL, XMAS (FIN+PSH+URG), SYN+FIN, SYN+RST - nie występują w poprawnym "
              "ruchu. Nadmiar RST: >= 100 pakietów RST stanowiących >= 30% ruchu hosta.");
    snprintf(t, sizeof t, "Retransmisje: alarm, gdy odsetek retransmisji przekracza %.1f%% segmentów z danymi "
                          "(wysoki poziom powyżej %.1f%%). Zerowe okno: >= 3 ogłoszenia w połączeniu.",
             o->retrans_pct, o->retrans_pct * 3);
    bullet(r, t);
    bullet(r, "DNS: nazwy z etykietą >= 40 znaków, długością >= 90 znaków lub entropią Shannona >= 3,8 przy "
              "etykiecie >= 24 znaków; >= 5 takich nazw w jednej domenie = możliwy tunel DNS. Wysoki "
              "odsetek NXDOMAIN (>= 25% przy >= 20 odpowiedziach) wskazuje na DGA.");
    snprintf(t, sizeof t, "Beaconing: >= %d połączeń od klienta do tej samej usługi w odstępach o "
                          "współczynniku zmienności <= %.2f i średniej >= 1 s (bez DNS/NTP/mDNS/SSDP).",
             o->beacon_min, o->beacon_cv);
    bullet(r, t);
    {
        char b[32];
        snprintf(t, sizeof t, "Duży transfer wychodzący: klient wysłał >= %s danych i co najmniej 4x więcej "
                              "niż odebrał.",
                 fmt_bytes((double)o->exfil_bytes, b, sizeof b));
    }
    bullet(r, t);
    bullet(r, "Ryzykowne usługi: aktywne sesje protokołów jawnotekstowych (Telnet, FTP, POP3, IMAP, TFTP, SNMP, "
              "HTTP) oraz portów kojarzonych z narzędziami ofensywnymi i backdoorami (4444, 31337, 1337, 6667, 12345).");
    h2(r, "Ograniczenia");
    para(r, "Analiza jest pasywna i heurystyczna: wyniki należy traktować jako wskazówki do dalszej weryfikacji, "
            "a nie dowód ataku. Fragmenty IP nie są składane, a ruch szyfrowany (TLS, QUIC) jest oceniany "
            "wyłącznie na podstawie metadanych. Liczniki retransmisji zależą od miejsca przechwytu - utrata "
            "pakietów za sondą nie jest widoczna. Progi detekcji można zmienić parametrami wiersza poleceń.");

    h2(r, "Wygenerowane pliki");
    static const col_t cols[2] = {{"Plik PNG", 0.40, 0}, {"Zawartość", 0.60, 0}};
    cells_t c = {0};
    for (int i = 0; i < CH_COUNT; i++) {
        cell(&c, "%s", in->charts[i].file);
        cell(&c, "%s", in->charts[i].caption);
    }
    table(r, cols, 2, c.v, CH_COUNT);
    cells_free(&c);
}

int report_pdf(const report_input_t *in, const char *path)
{
    rep_t r = {0};
    r.pdf = pdf_new("Raport analizy ruchu sieciowego TCP/UDP", TOOL_NAME " " TOOL_VERSION);
    for (int i = 0; i < CH_COUNT; i++)
        if (in->charts[i].cv) in->charts[i].pdf_img = pdf_image_add(r.pdf, in->charts[i].cv);

    section_cover(&r, in);
    section_capture(&r, in);
    section_traffic(&r, in);
    section_hosts(&r, in);
    section_tcp(&r, in);
    section_udp(&r, in);
    section_anomalies(&r, in);
    section_method(&r, in);
    draw_toc(&r);
    draw_footers(&r, in->an);

    int rc = pdf_save(r.pdf, path);
    pdf_free(r.pdf);
    return rc;
}

/* ------------------------------------------------------------------ console */

void report_console(const report_input_t *in, FILE *out)
{
    const analysis_t *an = in->an;
    char b1[64], b2[64], b3[64];
    double dur = an->last_ts - an->first_ts;
    fprintf(out, "\n=== Podsumowanie ===\n");
    fprintf(out, "Pakiety:        %s (%s)\n", fmt_int(an->packets, b1, sizeof b1), fmt_bytes((double)an->bytes, b2, sizeof b2));
    fprintf(out, "Czas trwania:   %s, średnio %s\n", fmt_duration(dur, b1, sizeof b1),
            fmt_bitrate(dur > 0 ? (double)an->bytes * 8 / dur : 0, b3, sizeof b3));
    fprintf(out, "TCP:            %llu pakietów, %llu połączeń, retransmisje %.2f%%\n",
            (unsigned long long)an->proto[P_TCP].pkts, (unsigned long long)an->tcp_flows,
            pct(an->tcp_retrans, an->tcp_data_segs));
    fprintf(out, "UDP:            %llu pakietów, %llu przepływów\n", (unsigned long long)an->proto[P_UDP].pkts,
            (unsigned long long)an->udp_flows);
    fprintf(out, "Hosty:          %zu, DNS: %llu zapytań\n", an->nhosts, (unsigned long long)an->dns_queries);
    fprintf(out, "Nieprawidłowości: %zu\n", in->al->n);
    for (size_t i = 0; i < in->al->n; i++)
        fprintf(out, "  [%-6s] %s\n", SEV_NAMES[in->al->v[i].sev], in->al->v[i].title);
}

/* ------------------------------------------------------------------ CSV */

static void csv_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        if (*s == '"') fputc('"', f);
        fputc(*s, f);
    }
    fputc('"', f);
}

int report_flows_csv(const analysis_t *an, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "proto,client,client_port,server,server_port,first_ts,last_ts,duration_s,pkts_c2s,pkts_s2c,"
               "bytes_c2s,bytes_s2c,payload_c2s,payload_s2c,tcp_state,rtt_ms,retrans,zero_window\n");
    char c[64], s[64];
    for (size_t i = 0; i < an->nflows; i++) {
        const flow_t *fl = &an->flows[i];
        int tcp = fl->proto == IPPROTO_TCP_;
        fprintf(f, "%s,%s,%u,%s,%u,%.6f,%.6f,%.6f,%llu,%llu,%llu,%llu,%llu,%llu,", tcp ? "TCP" : "UDP",
                addr_str(&fl->cli, c, sizeof c), fl->cport, addr_str(&fl->srv, s, sizeof s), fl->sport, fl->first,
                fl->last, fl->last - fl->first, (unsigned long long)fl->pkts[0], (unsigned long long)fl->pkts[1],
                (unsigned long long)fl->bytes[0], (unsigned long long)fl->bytes[1],
                (unsigned long long)fl->payload[0], (unsigned long long)fl->payload[1]);
        csv_str(f, tcp ? TCS_NAMES[fl->state] : "");
        if (fl->rtt >= 0) fprintf(f, ",%.3f", fl->rtt * 1000.0);
        else fprintf(f, ",");
        fprintf(f, ",%u,%u\n", fl->retrans[0] + fl->retrans[1], fl->zero_win[0] + fl->zero_win[1]);
    }
    return fclose(f) == 0 ? 0 : -1;
}
