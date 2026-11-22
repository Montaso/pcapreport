/*
 * raster.h - minimal RGB software rasterizer with a built-in 5x7 bitmap
 * font (ASCII + Polish diacritics, UTF-8 input). Used to draw charts.
 */
#ifndef RASTER_H
#define RASTER_H

#include <stdint.h>

typedef uint32_t rgb_t; /* 0xRRGGBB */

typedef struct {
    int      w, h;
    uint8_t *px;          /* w*h*3 bytes, row-major RGB */
} canvas_t;

canvas_t *cv_new(int w, int h, rgb_t bg);
void cv_free(canvas_t *c);

void cv_pixel(canvas_t *c, int x, int y, rgb_t col);
void cv_blend(canvas_t *c, int x, int y, rgb_t col, double alpha);
void cv_fill_rect(canvas_t *c, int x, int y, int w, int h, rgb_t col);
/* bar with rounded data-end: top corners (vertical) or right corners (horizontal) */
void cv_fill_bar(canvas_t *c, int x, int y, int w, int h, int r, rgb_t col, int horizontal);
void cv_hline(canvas_t *c, int x0, int x1, int y, rgb_t col);
void cv_vline(canvas_t *c, int x, int y0, int y1, rgb_t col);
/* anti-aliased line of given width */
void cv_line(canvas_t *c, double x0, double y0, double x1, double y1, double width, rgb_t col);
void cv_fill_circle(canvas_t *c, double cx, double cy, double r, rgb_t col);
/* annulus sector, angles in radians, 0 = 12 o'clock, clockwise */
void cv_ring_sector(canvas_t *c, double cx, double cy, double r0, double r1, double a0, double a1, rgb_t col);
/* polygon fill under a polyline down to baseline y (area charts) */
void cv_fill_area(canvas_t *c, const double *xs, const double *ys, int n, double base, rgb_t col, double alpha);

/* text: scale = integer pixel multiplier, glyph cell is 6x9 units (5x7 + descender) */
int  cv_text_width(const char *utf8, int scale);
int  cv_text_height(int scale);
void cv_text(canvas_t *c, int x, int y, const char *utf8, rgb_t col, int scale);
/* rotated 90 deg counter-clockwise, (x,y) = bottom-left of the text run */
void cv_text_vert(canvas_t *c, int x, int y, const char *utf8, rgb_t col, int scale);

#endif
