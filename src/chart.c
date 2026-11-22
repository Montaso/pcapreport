#include "chart.h"
#include "common.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const rgb_t SERIES_COLORS[8] = {C_S1, C_S2, C_S3, C_S4, C_S5, C_S6, C_S7, C_S8};

#define TS 2           /* label text scale */
#define TITLE_SCALE 3
#define PAD 36

/* ------------------------------------------------------------------ helpers */

void fmt_value(double v, value_fmt_t f, char *buf, size_t len)
{
    char t[48];
    if (v == 0) { snprintf(buf, len, "0"); return; }
    switch (f) {
    case VF_BYTES: fmt_bytes(v, buf, len); break;
    case VF_BITRATE: fmt_bitrate(v, buf, len); break;
    case VF_MS:
        if (v < 10) snprintf(buf, len, "%.2f ms", v);
        else snprintf(buf, len, "%.0f ms", v);
        break;
    case VF_PPS: snprintf(buf, len, "%s pkt/s", fmt_si(v, t, sizeof t)); break;
    default: fmt_si(v, buf, len); break;
    }
}

static int utf8_len1(const char *s)
{
    unsigned char c = (unsigned char)*s;
    if (c < 0x80) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    return 4;
}

/* truncate to fit max pixel width, appending ".." */
static void fit_text(const char *s, int maxw, int scale, char *out, size_t len)
{
    if (cv_text_width(s, scale) <= maxw) { snprintf(out, len, "%s", s); return; }
    int maxch = (maxw / scale + 1) / 6 - 2;
    size_t o = 0;
    const char *p = s;
    for (int i = 0; i < maxch && *p; i++) {
        int l = utf8_len1(p);
        if (o + (size_t)l + 3 >= len) break;
        memcpy(out + o, p, (size_t)l);
        o += (size_t)l;
        p += l;
    }
    memcpy(out + o, "..", 3);
}

static double nice_num(double x)
{
    if (x <= 0) return 1;
    double e = floor(log10(x));
    double f = x / pow(10, e);
    double nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
    return nf * pow(10, e);
}

static void nice_scale(double max, int nticks, double *step, double *top)
{
    if (!(max > 0)) max = 1;
    *step = nice_num(max / nticks);
    *top = ceil(max / *step - 1e-9) * *step;
    if (*top <= 0) *top = *step;
}

static int draw_header(canvas_t *c, const chart_opts_t *o)
{
    int y = 26;
    if (o->title) {
        cv_text(c, PAD, y, o->title, C_INK, TITLE_SCALE);
        y += cv_text_height(TITLE_SCALE) + 12;
    }
    if (o->subtitle) {
        cv_text(c, PAD, y, o->subtitle, C_INK2, TS);
        y += cv_text_height(TS) + 10;
    }
    return y + 6;
}

/* legend row: returns new top */
static int draw_legend(canvas_t *c, const char *const *names, const rgb_t *cols, int n, int y)
{
    int x = PAD;
    int sq = 14;
    for (int i = 0; i < n; i++) {
        int w = sq + 8 + cv_text_width(names[i], TS) + 26;
        if (x + w > c->w - PAD && x > PAD) { x = PAD; y += cv_text_height(TS) + 10; }
        cv_fill_bar(c, x, y + 1, sq, sq, 3, cols[i], 0);
        cv_text(c, x + sq + 8, y + 1, names[i], C_INK2, TS);
        x += w;
    }
    return y + cv_text_height(TS) + 16;
}

static void draw_no_data(canvas_t *c, int top)
{
    const char *m = "Brak danych do wyświetlenia";
    int w = cv_text_width(m, TS);
    cv_text(c, (c->w - w) / 2, (top + c->h) / 2, m, C_MUTED, TS);
}

/* y axis with gridlines; returns scale top */
static void draw_y_axis(canvas_t *c, int x0, int x1, int y0, int y1, double step, double top, value_fmt_t f)
{
    char buf[48];
    for (double v = 0; v <= top + step * 0.01; v += step) {
        int y = (int)lround(y1 - v / top * (y1 - y0));
        if (v > 0) cv_hline(c, x0, x1, y, C_GRID);
        fmt_value(v, f, buf, sizeof buf);
        int w = cv_text_width(buf, TS);
        cv_text(c, x0 - 12 - w, y - cv_text_height(TS) / 2 + 2, buf, C_MUTED, TS);
    }
}

static int y_labels_width(double step, double top, value_fmt_t f)
{
    char buf[48];
    int mw = 0;
    for (double v = 0; v <= top + step * 0.01; v += step) {
        fmt_value(v, f, buf, sizeof buf);
        int w = cv_text_width(buf, TS);
        if (w > mw) mw = w;
    }
    return mw;
}

static void draw_axis_titles(canvas_t *c, const chart_opts_t *o, int x0, int x1, int y0, int y1)
{
    if (o->ylabel) {
        int w = cv_text_width(o->ylabel, TS);
        cv_text_vert(c, 12, (y0 + y1) / 2 + w / 2, o->ylabel, C_INK2, TS);
    }
    if (o->xlabel) {
        int w = cv_text_width(o->xlabel, TS);
        cv_text(c, (x0 + x1 - w) / 2, c->h - cv_text_height(TS) - 14, o->xlabel, C_INK2, TS);
    }
}

static void fmt_reltime(double t, double span, char *buf, size_t len)
{
    if (span < 1) snprintf(buf, len, "%.0f ms", t * 1000);
    else if (span < 10) snprintf(buf, len, "%.1f s", t);
    else if (span < 180) snprintf(buf, len, "%.0f s", t);
    else if (span < 3 * 3600) snprintf(buf, len, "%d:%02d", (int)(t / 60), (int)fmod(t, 60));
    else snprintf(buf, len, "%dh%02d", (int)(t / 3600), (int)fmod(t / 60, 60));
}

static double time_step(double span)
{
    static const double steps[] = {0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15,
                                   30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400};
    double want = span / 8;
    for (size_t i = 0; i < ARRAY_LEN(steps); i++)
        if (steps[i] >= want) return steps[i];
    return ceil(want / 86400) * 86400;
}

/* ------------------------------------------------------------------ line */

canvas_t *chart_line(const chart_opts_t *o, const double *x, int n, const series_t *s, int ns)
{
    canvas_t *c = cv_new(o->w, o->h, C_SURFACE);
    int top = draw_header(c, o);
    if (ns >= 2) {
        const char *names[8];
        rgb_t cols[8];
        for (int i = 0; i < ns && i < 8; i++) { names[i] = s[i].name; cols[i] = s[i].color; }
        top = draw_legend(c, names, cols, MIN(ns, 8), top);
    }
    double ymax = 0;
    for (int k = 0; k < ns; k++)
        for (int i = 0; i < n; i++) ymax = MAX(ymax, s[k].v[i]);
    if (n <= 0 || ymax <= 0) { draw_no_data(c, top); return c; }

    double step, ytop;
    nice_scale(ymax, 5, &step, &ytop);
    int lw = y_labels_width(step, ytop, o->fmt);
    int x0 = PAD + (o->ylabel ? 30 : 0) + lw + 14, x1 = c->w - PAD - 10;
    int y0 = top + 10, y1 = c->h - 50 - (o->xlabel ? 34 : 0);
    draw_y_axis(c, x0, x1, y0, y1, step, ytop, o->fmt);

    double span = x[n - 1] > 0 ? x[n - 1] : 1;
    double ts = time_step(span);
    char buf[48];
    for (double t = 0; t <= span + ts * 0.01; t += ts) {
        int px = (int)lround(x0 + t / span * (x1 - x0));
        cv_vline(c, px, y1, y1 + 6, C_AXIS);
        fmt_reltime(t, span, buf, sizeof buf);
        int w = cv_text_width(buf, TS);
        int lx = px - w / 2;
        if (lx + w > c->w - 4) lx = c->w - 4 - w;
        cv_text(c, lx, y1 + 14, buf, C_MUTED, TS);
    }

    double *xs = xmalloc(sizeof(double) * (size_t)n);
    double *ys = xmalloc(sizeof(double) * (size_t)n);
    for (int k = 0; k < ns; k++) {
        for (int i = 0; i < n; i++) {
            xs[i] = x0 + x[i] / span * (x1 - x0);
            ys[i] = y1 - s[k].v[i] / ytop * (y1 - y0);
        }
        cv_fill_area(c, xs, ys, n, y1, s[k].color, ns == 1 ? 0.14 : 0.07);
    }
    for (int k = 0; k < ns; k++) {
        for (int i = 0; i < n; i++) {
            xs[i] = x0 + x[i] / span * (x1 - x0);
            ys[i] = y1 - s[k].v[i] / ytop * (y1 - y0);
        }
        if (n == 1) cv_fill_circle(c, xs[0], ys[0], 5, s[k].color);
        for (int i = 0; i + 1 < n; i++) cv_line(c, xs[i], ys[i], xs[i + 1], ys[i + 1], 2.5, s[k].color);
    }
    free(xs);
    free(ys);
    cv_fill_rect(c, x0, y1, x1 - x0 + 1, 2, C_AXIS);
    draw_axis_titles(c, o, x0, x1, y0, y1);
    return c;
}

/* ------------------------------------------------------------------ vertical bars */

static canvas_t *vbars_impl(const chart_opts_t *o, const char *const *cats, int nc, const series_t *s, int ns,
                            int stacked, const double *single, const rgb_t *catcol, const char *const *legend,
                            const rgb_t *legend_col, int nlegend)
{
    canvas_t *c = cv_new(o->w, o->h, C_SURFACE);
    int top = draw_header(c, o);
    if (nlegend > 0) top = draw_legend(c, legend, legend_col, nlegend, top);
    else if (ns >= 2) {
        const char *names[8];
        rgb_t cols[8];
        for (int i = 0; i < ns && i < 8; i++) { names[i] = s[i].name; cols[i] = s[i].color; }
        top = draw_legend(c, names, cols, MIN(ns, 8), top);
    }
    int nser = single ? 1 : ns;
    double ymax = 0;
    for (int i = 0; i < nc; i++) {
        double sum = 0;
        for (int k = 0; k < nser; k++) {
            double v = single ? single[i] : s[k].v[i];
            if (stacked) sum += v;
            else ymax = MAX(ymax, v);
        }
        if (stacked) ymax = MAX(ymax, sum);
    }
    if (nc <= 0 || ymax <= 0) { draw_no_data(c, top); return c; }

    double step, ytop;
    nice_scale(ymax * 1.08, 5, &step, &ytop);
    int lw = y_labels_width(step, ytop, o->fmt);
    int x0 = PAD + (o->ylabel ? 30 : 0) + lw + 14, x1 = c->w - PAD - 10;
    int y0 = top + 14, y1 = c->h - 56 - (o->xlabel ? 34 : 0);
    draw_y_axis(c, x0, x1, y0, y1, step, ytop, o->fmt);

    double gw = (double)(x1 - x0) / nc;
    int groups_bar = (int)(gw * 0.72);
    int bw = stacked || nser == 1 ? groups_bar : (groups_bar - 2 * (nser - 1)) / nser;
    if (bw < 2) bw = 2;
    char buf[64], lab[64];
    for (int i = 0; i < nc; i++) {
        double gx = x0 + gw * i + (gw - groups_bar) / 2.0;
        double acc = 0;
        for (int k = 0; k < nser; k++) {
            double v = single ? single[i] : s[k].v[i];
            rgb_t col = single ? (catcol ? catcol[i] : C_S1) : s[k].color;
            if (v <= 0) continue;
            int bx, by, bh;
            if (stacked) {
                int ya = (int)lround(y1 - acc / ytop * (y1 - y0));
                int yb = (int)lround(y1 - (acc + v) / ytop * (y1 - y0));
                bx = (int)lround(gx);
                by = yb;
                bh = ya - yb - (acc > 0 ? 2 : 0);   /* 2px surface gap between segments */
                int is_top = 1;
                for (int q = k + 1; q < nser; q++) if ((single ? 0 : s[q].v[i]) > 0) is_top = 0;
                if (bh < 1) bh = 1;
                if (is_top) cv_fill_bar(c, bx, by, bw, bh, 4, col, 0);
                else cv_fill_rect(c, bx, by, bw, bh, col);
                acc += v;
            } else {
                bx = (int)lround(gx + k * (bw + 2));
                by = (int)lround(y1 - v / ytop * (y1 - y0));
                bh = y1 - by;
                if (bh < 1) { bh = 1; by = y1 - 1; }
                cv_fill_bar(c, bx, by, bw, bh, 4, col, 0);
                if (nser == 1) {
                    fmt_value(v, o->fmt == VF_MS ? VF_COUNT : o->fmt, buf, sizeof buf);
                    int w = cv_text_width(buf, TS);
                    if (w <= gw) cv_text(c, bx + (bw - w) / 2, by - cv_text_height(TS) - 2, buf, C_INK2, TS);
                }
            }
        }
        if (stacked && acc > 0) {
            fmt_value(acc, o->fmt, buf, sizeof buf);
            int w = cv_text_width(buf, TS);
            int by = (int)lround(y1 - acc / ytop * (y1 - y0));
            if (w <= gw) cv_text(c, (int)lround(gx) + (bw - w) / 2, by - cv_text_height(TS) - 2, buf, C_INK2, TS);
        }
        fit_text(cats[i], (int)gw - 6, TS, lab, sizeof lab);
        int w = cv_text_width(lab, TS);
        cv_text(c, (int)lround(x0 + gw * i + (gw - w) / 2), y1 + 12, lab, C_INK2, TS);
    }
    cv_fill_rect(c, x0, y1, x1 - x0 + 1, 2, C_AXIS);
    draw_axis_titles(c, o, x0, x1, y0, y1);
    return c;
}

canvas_t *chart_vbars(const chart_opts_t *o, const char *const *cats, int nc, const series_t *s, int ns, int stacked)
{
    return vbars_impl(o, cats, nc, s, ns, stacked, NULL, NULL, NULL, NULL, 0);
}

/* ------------------------------------------------------------------ horizontal bars */

canvas_t *chart_hbars(const chart_opts_t *o, const char *const *cats, int nc, const series_t *s, int ns)
{
    canvas_t *c = cv_new(o->w, o->h, C_SURFACE);
    int top = draw_header(c, o);
    if (ns >= 2) {
        const char *names[8];
        rgb_t cols[8];
        for (int i = 0; i < ns && i < 8; i++) { names[i] = s[i].name; cols[i] = s[i].color; }
        top = draw_legend(c, names, cols, MIN(ns, 8), top);
    }
    double vmax = 0;
    for (int i = 0; i < nc; i++) {
        double sum = 0;
        for (int k = 0; k < ns; k++) sum += s[k].v[i];
        vmax = MAX(vmax, sum);
    }
    if (nc <= 0 || vmax <= 0) { draw_no_data(c, top); return c; }

    int labw = 0;
    for (int i = 0; i < nc; i++) labw = MAX(labw, cv_text_width(cats[i], TS));
    labw = MIN(labw, c->w * 2 / 5);
    char vb[48];
    fmt_value(vmax, o->fmt, vb, sizeof vb);
    int valw = cv_text_width(vb, TS) + 16;

    int x0 = PAD + labw + 16, x1 = c->w - PAD - valw;
    int y0 = top + 4, y1 = c->h - 30;
    double rh = (double)(y1 - y0) / nc;
    int bh = (int)MIN(rh * 0.66, 44.0);
    if (bh < 4) bh = 4;

    /* light vertical gridlines */
    double step, vtop;
    nice_scale(vmax, 4, &step, &vtop);
    for (double v = step; v <= vtop + step * 0.01; v += step) {
        int gx = (int)lround(x0 + v / vtop * (x1 - x0));
        if (gx <= x1) cv_vline(c, gx, y0, y1, C_GRID);
    }

    char lab[96];
    for (int i = 0; i < nc; i++) {
        int by = (int)lround(y0 + rh * i + (rh - bh) / 2);
        fit_text(cats[i], labw, TS, lab, sizeof lab);
        int lw = cv_text_width(lab, TS);
        cv_text(c, x0 - 14 - lw, by + (bh - cv_text_height(TS)) / 2 + 2, lab, C_INK, TS);
        double acc = 0;
        int last_k = -1;
        for (int k = 0; k < ns; k++) if (s[k].v[i] > 0) last_k = k;
        for (int k = 0; k < ns; k++) {
            double v = s[k].v[i];
            if (v <= 0) continue;
            int xa = (int)lround(x0 + acc / vtop * (x1 - x0)) + (acc > 0 ? 2 : 0);
            int xb = (int)lround(x0 + (acc + v) / vtop * (x1 - x0));
            int w = MAX(xb - xa, 1);
            if (k == last_k) cv_fill_bar(c, xa, by, w, bh, 4, s[k].color, 1);
            else cv_fill_rect(c, xa, by, w, bh, s[k].color);
            acc += v;
        }
        fmt_value(acc, o->fmt, vb, sizeof vb);
        int vx = (int)lround(x0 + acc / vtop * (x1 - x0)) + 10;
        cv_text(c, vx, by + (bh - cv_text_height(TS)) / 2 + 2, vb, C_INK2, TS);
    }
    cv_fill_rect(c, x0 - 1, y0, 2, y1 - y0, C_AXIS);
    draw_axis_titles(c, o, x0, x1, y0, y1);
    return c;
}

/* ------------------------------------------------------------------ donut */

canvas_t *chart_donut(const chart_opts_t *o, const char *const *labels, const double *v, const rgb_t *colors,
                      int n, const char *center_top, const char *center_bottom)
{
    const double TAU = 6.283185307179586;
    canvas_t *c = cv_new(o->w, o->h, C_SURFACE);
    int top = draw_header(c, o);
    double total = 0;
    for (int i = 0; i < n; i++) total += v[i] > 0 ? v[i] : 0;
    if (total <= 0) { draw_no_data(c, top); return c; }

    double R = MIN((c->h - top - 30) / 2.0, c->w * 0.22);
    double r0 = R * 0.62;
    double cx = PAD + 20 + R, cy = top + (c->h - top - 10) / 2.0;
    double a = 0;
    for (int i = 0; i < n; i++) {
        if (v[i] <= 0) continue;
        double a1 = a + v[i] / total * TAU;
        cv_ring_sector(c, cx, cy, r0, R, a, a1, colors[i]);
        a = a1;
    }
    /* 2px surface gaps between segments */
    int nonzero = 0;
    for (int i = 0; i < n; i++) if (v[i] > 0) nonzero++;
    if (nonzero > 1) {
        a = 0;
        for (int i = 0; i < n; i++) {
            if (v[i] <= 0) continue;
            cv_line(c, cx + sin(a) * (r0 - 2), cy - cos(a) * (r0 - 2), cx + sin(a) * (R + 2), cy - cos(a) * (R + 2),
                    3.0, C_SURFACE);
            a += v[i] / total * TAU;
        }
    }
    if (center_top) {
        int w = cv_text_width(center_top, TITLE_SCALE);
        cv_text(c, (int)(cx - w / 2), (int)(cy - cv_text_height(TITLE_SCALE)), center_top, C_INK, TITLE_SCALE);
    }
    if (center_bottom) {
        int w = cv_text_width(center_bottom, TS);
        cv_text(c, (int)(cx - w / 2), (int)(cy + 8), center_bottom, C_MUTED, TS);
    }

    /* legend table on the right */
    int lx = (int)(cx + R + 60);
    int lh = cv_text_height(TS) + 18;
    int ly = (int)(cy - (n * lh) / 2.0);
    char buf[64], pct[32];
    for (int i = 0; i < n; i++) {
        int y = ly + i * lh;
        cv_fill_bar(c, lx, y, 16, 16, 3, colors[i], 0);
        cv_text(c, lx + 28, y + 2, labels[i], C_INK, TS);
        snprintf(pct, sizeof pct, "%.1f%%", 100.0 * (v[i] > 0 ? v[i] : 0) / total);
        cv_text(c, lx + 300, y + 2, pct, C_INK, TS);
        fmt_value(v[i], o->fmt, buf, sizeof buf);
        cv_text(c, lx + 420, y + 2, buf, C_MUTED, TS);
    }
    return c;
}
