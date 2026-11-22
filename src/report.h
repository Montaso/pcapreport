/*
 * report.h - lays out the PDF report (summary, statistics, charts,
 * tables, anomalies, methodology).
 */
#ifndef REPORT_H
#define REPORT_H

#include "analyzer.h"
#include "anomaly.h"
#include "charts.h"

typedef struct {
    const analysis_t      *an;
    const anomaly_list_t  *al;
    const detect_opts_t   *dopts;
    const analysis_opts_t *aopts;
    chart_out_t           *charts;   /* CH_COUNT entries */
    int                    topn;
} report_input_t;

int report_pdf(const report_input_t *in, const char *path);

/* short textual summary for the terminal */
void report_console(const report_input_t *in, FILE *out);

/* CSV export of all flows */
int report_flows_csv(const analysis_t *an, const char *path);

#endif
