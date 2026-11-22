/*
 * anomaly.h - heuristic detection of suspicious or abnormal traffic
 * patterns on top of the flow table built by the analyzer.
 */
#ifndef ANOMALY_H
#define ANOMALY_H

#include "analyzer.h"

typedef enum { SEV_INFO = 0, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_COUNT } severity_t;
extern const char *const SEV_NAMES[SEV_COUNT];

typedef enum {
    AC_PORTSCAN = 0,
    AC_SWEEP,
    AC_SYNFLOOD,
    AC_UDPFLOOD,
    AC_BADFLAGS,
    AC_RST,
    AC_RETRANS,
    AC_ZEROWIN,
    AC_DNS,
    AC_BEACON,
    AC_EXFIL,
    AC_PORTS,
    AC_CAPTURE,
    AC_COUNT
} anomaly_cat_t;
extern const char *const AC_NAMES[AC_COUNT];

typedef struct {
    severity_t    sev;
    anomaly_cat_t cat;
    char          title[160];
    char          detail[600];
    double        first, last;    /* time window, 0 if n/a */
    uint64_t      count;          /* main magnitude (ports, packets, ...) */
} anomaly_t;

typedef struct {
    anomaly_t *v;
    size_t     n, cap;
} anomaly_list_t;

typedef struct {
    int      scan_ports;      /* distinct ports for a vertical port scan */
    int      sweep_hosts;     /* distinct hosts for a horizontal scan */
    int      synflood_min;    /* unanswered SYNs towards one target */
    double   synflood_rate;   /* SYN/s */
    double   udpflood_pps;    /* UDP packets/s towards one target */
    uint64_t udpflood_min;    /* minimum packets for UDP flood */
    double   retrans_pct;     /* global retransmission %, alert above */
    int      beacon_min;      /* minimum repeated connections */
    double   beacon_cv;       /* max coefficient of variation of intervals */
    uint64_t exfil_bytes;     /* client->server payload for a big upload */
} detect_opts_t;

void detect_opts_default(detect_opts_t *o);
void detect_anomalies(analysis_t *an, const detect_opts_t *o, anomaly_list_t *out);
void anomaly_list_free(anomaly_list_t *l);

#endif
