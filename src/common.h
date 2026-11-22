/*
 * common.h - shared helpers: byte-order readers, safe allocation,
 * IP address type and formatting.
 */
#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define TOOL_NAME    "pcapreport"
#define TOOL_VERSION "1.0.0"

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* ---- big/little endian readers (alignment safe) ---- */
static inline uint16_t rd16be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t rd32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint16_t rd16le(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ---- allocation that aborts on OOM ---- */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);

/* grow a dynamic array so that it can hold at least `need` elements */
#define VEC_RESERVE(ptr, cap, need)                                         \
    do {                                                                    \
        if ((size_t)(need) > (size_t)(cap)) {                               \
            size_t nc_ = (cap) ? (size_t)(cap) * 2 : 64;                    \
            while (nc_ < (size_t)(need)) nc_ *= 2;                          \
            (ptr) = xrealloc((ptr), nc_ * sizeof(*(ptr)));                  \
            (cap) = nc_;                                                    \
        }                                                                   \
    } while (0)

/* ---- IP address (v4 stored in first 4 bytes) ---- */
typedef struct {
    uint8_t ver;      /* 4 or 6, 0 = none */
    uint8_t a[16];
} addr_t;

int  addr_cmp(const addr_t *x, const addr_t *y);
/* writes textual form into buf (>= 46 bytes) and returns buf */
char *addr_str(const addr_t *a, char *buf, size_t len);
int  addr_is_private(const addr_t *a);
int  addr_is_multicast(const addr_t *a);

/* ---- growable string buffer ---- */
typedef struct {
    char  *data;
    size_t len, cap;
} sbuf_t;

void sb_append(sbuf_t *sb, const void *data, size_t n);
void sb_printf(sbuf_t *sb, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;
void sb_free(sbuf_t *sb);

/* ---- formatting helpers ---- */
/* human readable byte count: "1.23 MB" */
char *fmt_bytes(double v, char *buf, size_t len);
/* human readable count with SI suffix: "12.3 k" */
char *fmt_si(double v, char *buf, size_t len);
/* bit rate: "1.2 Mbit/s" */
char *fmt_bitrate(double bps, char *buf, size_t len);
/* duration: "1 h 02 min", "3.25 s", "12.4 ms" */
char *fmt_duration(double s, char *buf, size_t len);
/* UTC timestamp "2024-01-01 12:00:00.123" */
char *fmt_time(double ts, char *buf, size_t len);
/* integer with thin separators: "1 234 567" */
char *fmt_int(uint64_t v, char *buf, size_t len);

extern int g_verbose;
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);

#endif
