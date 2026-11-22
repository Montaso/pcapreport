#include "common.h"

#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int g_verbose = 1;

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) { fprintf(stderr, TOOL_NAME ": out of memory\n"); exit(2); }
    return p;
}

void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) { fprintf(stderr, TOOL_NAME ": out of memory\n"); exit(2); }
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) { fprintf(stderr, TOOL_NAME ": out of memory\n"); exit(2); }
    return q;
}

char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = xmalloc(n);
    memcpy(d, s, n);
    return d;
}

/* ------------------------------------------------------------------ */

int addr_cmp(const addr_t *x, const addr_t *y)
{
    if (x->ver != y->ver) return x->ver < y->ver ? -1 : 1;
    return memcmp(x->a, y->a, x->ver == 4 ? 4 : 16);
}

char *addr_str(const addr_t *a, char *buf, size_t len)
{
    if (a->ver == 4) {
        snprintf(buf, len, "%u.%u.%u.%u", a->a[0], a->a[1], a->a[2], a->a[3]);
        return buf;
    }
    if (a->ver != 6) { snprintf(buf, len, "-"); return buf; }

    /* RFC 5952: compress the longest run (>=2) of zero groups */
    uint16_t g[8];
    for (int i = 0; i < 8; i++) g[i] = rd16be(a->a + 2 * i);
    int best = -1, bestlen = 0;
    for (int i = 0; i < 8;) {
        if (g[i] == 0) {
            int j = i;
            while (j < 8 && g[j] == 0) j++;
            if (j - i > bestlen) { best = i; bestlen = j - i; }
            i = j;
        } else {
            i++;
        }
    }
    if (bestlen < 2) best = -1;

    size_t o = 0;
    buf[0] = 0;
    for (int i = 0; i < 8; i++) {
        if (i == best) {
            o += (size_t)snprintf(buf + o, o < len ? len - o : 0, "::");
            i += bestlen - 1;
            continue;
        }
        if (o > 0 && buf[o - 1] != ':')
            o += (size_t)snprintf(buf + o, o < len ? len - o : 0, ":");
        o += (size_t)snprintf(buf + o, o < len ? len - o : 0, "%x", g[i]);
    }
    return buf;
}

int addr_is_private(const addr_t *a)
{
    if (a->ver == 4) {
        const uint8_t *b = a->a;
        return b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) ||
               (b[0] == 192 && b[1] == 168) || b[0] == 127 ||
               (b[0] == 169 && b[1] == 254);
    }
    if (a->ver == 6)
        return (a->a[0] & 0xFE) == 0xFC || (a->a[0] == 0xFE && (a->a[1] & 0xC0) == 0x80);
    return 0;
}

int addr_is_multicast(const addr_t *a)
{
    if (a->ver == 4)
        return (a->a[0] & 0xF0) == 0xE0 ||
               (a->a[0] == 255 && a->a[1] == 255 && a->a[2] == 255 && a->a[3] == 255);
    if (a->ver == 6) return a->a[0] == 0xFF;
    return 0;
}

/* ------------------------------------------------------------------ */

void sb_append(sbuf_t *sb, const void *data, size_t n)
{
    VEC_RESERVE(sb->data, sb->cap, sb->len + n + 1);
    memcpy(sb->data + sb->len, data, n);
    sb->len += n;
    sb->data[sb->len] = 0;
}

void sb_printf(sbuf_t *sb, const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof tmp) { sb_append(sb, tmp, (size_t)n); return; }
    char *big = xmalloc((size_t)n + 1);
    va_start(ap, fmt);
    vsnprintf(big, (size_t)n + 1, fmt, ap);
    va_end(ap);
    sb_append(sb, big, (size_t)n);
    free(big);
}

void sb_free(sbuf_t *sb)
{
    free(sb->data);
    sb->data = NULL;
    sb->len = sb->cap = 0;
}

/* ------------------------------------------------------------------ */

char *fmt_bytes(double v, char *buf, size_t len)
{
    static const char *u[] = {"B", "kB", "MB", "GB", "TB", "PB"};
    int i = 0;
    while (v >= 1000.0 && i < 5) { v /= 1000.0; i++; }
    if (i == 0) snprintf(buf, len, "%.0f %s", v, u[i]);
    else snprintf(buf, len, v < 10 ? "%.2f %s" : v < 100 ? "%.1f %s" : "%.0f %s", v, u[i]);
    return buf;
}

char *fmt_si(double v, char *buf, size_t len)
{
    static const char *u[] = {"", "k", "M", "G", "T"};
    int i = 0;
    double a = v < 0 ? -v : v;
    while (a >= 1000.0 && i < 4) { a /= 1000.0; v /= 1000.0; i++; }
    if (i == 0) {
        if (a == (double)(long long)a) snprintf(buf, len, "%.0f", v);
        else snprintf(buf, len, a < 10 ? "%.2f" : "%.1f", v);
    } else {
        if (a < 10 && fabs(a - floor(a + 0.5)) > 0.05) snprintf(buf, len, "%.1f%s", v, u[i]);
        else snprintf(buf, len, "%.0f%s", v, u[i]);
    }
    return buf;
}

char *fmt_bitrate(double bps, char *buf, size_t len)
{
    static const char *u[] = {"bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"};
    int i = 0;
    while (bps >= 1000.0 && i < 4) { bps /= 1000.0; i++; }
    snprintf(buf, len, bps < 10 ? "%.2f %s" : bps < 100 ? "%.1f %s" : "%.0f %s", bps, u[i]);
    return buf;
}

char *fmt_duration(double s, char *buf, size_t len)
{
    if (s < 0) s = 0;
    if (s < 1e-3) snprintf(buf, len, "%.0f µs", s * 1e6);
    else if (s < 1.0) snprintf(buf, len, "%.1f ms", s * 1e3);
    else if (s < 60.0) snprintf(buf, len, "%.2f s", s);
    else if (s < 3600.0) snprintf(buf, len, "%d min %02d s", (int)(s / 60), (int)s % 60);
    else if (s < 86400.0) snprintf(buf, len, "%d h %02d min", (int)(s / 3600), ((int)s % 3600) / 60);
    else snprintf(buf, len, "%d d %02d h", (int)(s / 86400), ((int)s % 86400) / 3600);
    return buf;
}

char *fmt_time(double ts, char *buf, size_t len)
{
    time_t t = (time_t)ts;
    struct tm *tm = gmtime(&t);
    if (!tm) { snprintf(buf, len, "%.3f", ts); return buf; }
    int ms = (int)((ts - (double)t) * 1000.0);
    if (ms < 0) ms = 0;
    if (ms > 999) ms = 999;
    snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%03d", tm->tm_year + 1900, tm->tm_mon + 1,
             tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, ms);
    return buf;
}

char *fmt_int(uint64_t v, char *buf, size_t len)
{
    char tmp[32];
    int n = snprintf(tmp, sizeof tmp, "%llu", (unsigned long long)v);
    size_t o = 0;
    for (int i = 0; i < n && o + 2 < len; i++) {
        if (i > 0 && (n - i) % 3 == 0) buf[o++] = ' ';
        buf[o++] = tmp[i];
    }
    buf[o] = 0;
    return buf;
}

void log_info(const char *fmt, ...)
{
    if (!g_verbose) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void log_warn(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, TOOL_NAME ": warning: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
