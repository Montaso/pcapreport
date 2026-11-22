/*
 * pdf.h - minimal PDF 1.4 writer: A4 pages, the standard Helvetica /
 * Helvetica-Bold / Courier fonts (with a custom encoding that adds the
 * Polish letters), filled rectangles, lines and embedded RGB images.
 * Content streams and images are Flate-compressed with zlib.
 */
#ifndef PDF_H
#define PDF_H

#include "common.h"
#include "raster.h"

#define PDF_A4_W 595.28
#define PDF_A4_H 841.89

typedef enum { PDF_REG = 0, PDF_BOLD, PDF_MONO, PDF_FONT_COUNT } pdf_font_t;

typedef struct pdf pdf_t;

pdf_t *pdf_new(const char *title, const char *author);
void   pdf_free(pdf_t *p);

int    pdf_page_new(pdf_t *p);           /* returns page index */
int    pdf_page_count(const pdf_t *p);
void   pdf_set_page(pdf_t *p, int idx);  /* select page for drawing */

/* coordinates: origin top-left, y grows downward (converted internally) */
void   pdf_text(pdf_t *p, double x, double y, pdf_font_t f, double size, rgb_t col, const char *utf8);
double pdf_text_width(pdf_font_t f, double size, const char *utf8);
void   pdf_rect(pdf_t *p, double x, double y, double w, double h, rgb_t fill);
void   pdf_rect_stroke(pdf_t *p, double x, double y, double w, double h, double lw, rgb_t col);
void   pdf_line(pdf_t *p, double x0, double y0, double x1, double y1, double lw, rgb_t col);
/* link annotation to a page (internal navigation) */
void   pdf_link(pdf_t *p, double x, double y, double w, double h, int target_page);

int    pdf_image_add(pdf_t *p, const canvas_t *c);  /* returns image id */
void   pdf_image_draw(pdf_t *p, int id, double x, double y, double w, double h);

int    pdf_save(pdf_t *p, const char *path);

#endif
