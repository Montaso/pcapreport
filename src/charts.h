/*
 * charts.h - builds the concrete set of report charts from the analysis.
 */
#ifndef CHARTS_H
#define CHARTS_H

#include "analyzer.h"
#include "anomaly.h"
#include "raster.h"

enum {
    CH_THROUGHPUT = 0,
    CH_PPS,
    CH_PROTO,
    CH_SIZES,
    CH_TALKERS,
    CH_SERVICES,
    CH_FLAGS,
    CH_TCPSTATES,
    CH_RTT,
    CH_ANOMALIES,
    CH_COUNT
};

typedef struct {
    const char *file;      /* PNG file name */
    const char *caption;   /* caption used in the PDF */
    canvas_t   *cv;
    int         pdf_img;   /* image id in the PDF, -1 if not added */
} chart_out_t;

/* RTT histogram bins (ms) shared with the report tables */
#define RTT_BINS 9
extern const char *const RTT_BIN_LABELS[RTT_BINS];
int rtt_bin(double ms);

void charts_build(const analysis_t *an, const anomaly_list_t *al, int topn, chart_out_t out[CH_COUNT]);
/* writes all PNGs to dir; returns number of failures */
int  charts_write(chart_out_t out[CH_COUNT], const char *dir);
void charts_free(chart_out_t out[CH_COUNT]);

/* sorted index helpers shared with the report */
size_t *top_hosts(const analysis_t *an, size_t *n);     /* by total bytes, desc */
size_t *top_services(const analysis_t *an, size_t *n);  /* by bytes, desc */
size_t *top_flows(const analysis_t *an, uint8_t proto, size_t *n); /* by bytes, desc; proto 0 = all */
rgb_t   severity_color(int sev);

#endif
