/*
 * chart.h - chart primitives (line/area, vertical & horizontal bars, donut)
 * rendered onto RGB canvases. Colours follow a validated, colour-blind
 * aware categorical palette; status colours are reserved for severities.
 */
#ifndef CHART_H
#define CHART_H

#include <stddef.h>

#include "raster.h"

/* chrome */
#define C_SURFACE 0xFCFCFBu
#define C_INK     0x0B0B0Bu
#define C_INK2    0x52514Eu
#define C_MUTED   0x898781u
#define C_GRID    0xE1E0D9u
#define C_AXIS    0xC3C2B7u
/* categorical slots, fixed order */
#define C_S1 0x2A78D6u /* blue    */
#define C_S2 0xEB6834u /* orange  */
#define C_S3 0x1BAF7Au /* aqua    */
#define C_S4 0xEDA100u /* yellow  */
#define C_S5 0xE87BA4u /* magenta */
#define C_S6 0x008300u /* green   */
#define C_S7 0x6250D6u /* violet  */
#define C_S8 0xE34948u /* red     */
#define C_OTHER 0xA8A7A1u /* neutral grey for the "other" bucket */
/* status (severity) - never used for series identity */
#define C_GOOD     0x0CA30Cu
#define C_WARNING  0xFAB219u
#define C_SERIOUS  0xEC835Au
#define C_CRITICAL 0xD03B3Bu

extern const rgb_t SERIES_COLORS[8];

typedef enum { VF_COUNT = 0, VF_BYTES, VF_BITRATE, VF_MS, VF_PPS } value_fmt_t;

typedef struct {
    const char   *name;
    rgb_t         color;
    const double *v;
} series_t;

typedef struct {
    int         w, h;
    const char *title;
    const char *subtitle;
    const char *ylabel;
    const char *xlabel;
    value_fmt_t fmt;
} chart_opts_t;

/* x = seconds from start; one line per series, light area fill */
canvas_t *chart_line(const chart_opts_t *o, const double *x, int n, const series_t *s, int ns);
/* categories on X, grouped (stacked=0) or stacked bars */
canvas_t *chart_vbars(const chart_opts_t *o, const char *const *cats, int nc, const series_t *s, int ns,
                      int stacked);
/* categories as rows (labels left), stacked segments per series */
canvas_t *chart_hbars(const chart_opts_t *o, const char *const *cats, int nc, const series_t *s, int ns);
canvas_t *chart_donut(const chart_opts_t *o, const char *const *labels, const double *v, const rgb_t *colors,
                      int n, const char *center_top, const char *center_bottom);

void fmt_value(double v, value_fmt_t f, char *buf, size_t len);

#endif
