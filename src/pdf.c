#include "pdf.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

/* ------------------------------------------------------------------ fonts */

static const uint16_t W_HELV[95] = {
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, /* sp - / */
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556,                               /* 0-9 */
    278, 278, 584, 584, 584, 556, 1015,                                             /* : - @ */
    667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833,                /* A-M */
    722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611,                /* N-Z */
    278, 278, 278, 469, 556, 333,                                                   /* [ - ` */
    556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833,                /* a-m */
    556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500,                /* n-z */
    334, 260, 334, 584};
static const uint16_t W_HELVB[95] = {
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
    333, 333, 584, 584, 584, 611, 975,
    722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833,
    722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611,
    333, 278, 333, 584, 556, 333,
    556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889,
    611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500,
    389, 280, 389, 584};
/* codes 0x80..0x8F: Polish letters (see Differences below) */
static const uint16_t W_PL[16] = {667, 722, 667, 556, 722, 667, 611, 611, 556, 500, 556, 222, 556, 500, 500, 500};
static const uint16_t W_PLB[16] = {722, 722, 667, 611, 722, 667, 611, 611, 556, 556, 556, 278, 611, 556, 500, 500};

static const char *const DIFFERENCES =
    "[128 /Aogonek /Cacute /Eogonek /Lslash /Nacute /Sacute /Zacute /Zdotaccent "
    "/aogonek /cacute /eogonek /lslash /nacute /sacute /zacute /zdotaccent]";

static double glyph_w(pdf_font_t f, uint8_t b)
{
    if (f == PDF_MONO) return 600;
    int bold = f == PDF_BOLD;
    if (b >= 32 && b <= 126) return bold ? W_HELVB[b - 32] : W_HELV[b - 32];
    if (b >= 0x80 && b <= 0x8F) return bold ? W_PLB[b - 0x80] : W_PL[b - 0x80];
    switch (b) {
    case 0x95: return 350;
    case 0x96: return 556;
    case 0x97: return 1000;
    case 0xB0: return 400;
    case 0xB5: return bold ? 611 : 556;
    case 0xD7: return 584;
    case 0xD3: return 778;
    case 0xF3: return bold ? 611 : 556;
    default: break;
    }
    if (b >= 0xE0) return bold ? 590 : 556;
    if (b >= 0xC0) return 722;
    return 400;
}

/* UTF-8 -> single-byte font encoding. Returns encoded length. */
static size_t encode_text(const char *s, uint8_t *out, size_t cap)
{
    static const struct { uint32_t cp; uint8_t b; } PL[] = {
        {0x0104, 0x80}, {0x0106, 0x81}, {0x0118, 0x82}, {0x0141, 0x83}, {0x0143, 0x84}, {0x015A, 0x85},
        {0x0179, 0x86}, {0x017B, 0x87}, {0x0105, 0x88}, {0x0107, 0x89}, {0x0119, 0x8A}, {0x0142, 0x8B},
        {0x0144, 0x8C}, {0x015B, 0x8D}, {0x017A, 0x8E}, {0x017C, 0x8F}, {0x2022, 0x95}, {0x2013, 0x96},
        {0x2014, 0x97}};
    size_t o = 0;
    const uint8_t *p = (const uint8_t *)s;
    while (*p && o + 4 < cap) {
        uint32_t cp;
        if (p[0] < 0x80) { cp = *p++; }
        else if ((p[0] & 0xE0) == 0xC0 && p[1]) { cp = ((uint32_t)(p[0] & 0x1F) << 6) | (p[1] & 0x3F); p += 2; }
        else if ((p[0] & 0xF0) == 0xE0 && p[1] && p[2]) {
            cp = ((uint32_t)(p[0] & 0x0F) << 12) | ((uint32_t)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
            p += 3;
        } else { p++; cp = '?'; }

        if (cp >= 32 && cp <= 126) { out[o++] = (uint8_t)cp; continue; }
        if (cp >= 0xA0 && cp <= 0xFF) { out[o++] = (uint8_t)cp; continue; }
        int done = 0;
        for (size_t i = 0; i < ARRAY_LEN(PL); i++)
            if (PL[i].cp == cp) { out[o++] = PL[i].b; done = 1; break; }
        if (done) continue;
        if (cp == 0x2192) { out[o++] = '-'; out[o++] = '>'; }
        else if (cp == 0x2264) { out[o++] = '<'; out[o++] = '='; }
        else if (cp == 0x2265) { out[o++] = '>'; out[o++] = '='; }
        else if (cp == 0x2026) { out[o++] = '.'; out[o++] = '.'; out[o++] = '.'; }
        else if (cp == '\t') out[o++] = ' ';
        else out[o++] = '?';
    }
    return o;
}

double pdf_text_width(pdf_font_t f, double size, const char *s)
{
    uint8_t buf[2048];
    size_t n = encode_text(s, buf, sizeof buf);
    double w = 0;
    for (size_t i = 0; i < n; i++) w += glyph_w(f, buf[i]);
    return w * size / 1000.0;
}

/* ------------------------------------------------------------------ document */

typedef struct {
    double x, y, w, h;
    int    target;
} link_t;

typedef struct {
    sbuf_t  content;
    link_t *links;
    size_t  nlinks, clinks;
} page_t;

typedef struct {
    int      w, h;
    uint8_t *z;
    size_t   zlen;
} image_t;

struct pdf {
    char    *title, *author;
    page_t  *pages;
    size_t   npages, cpages;
    int      cur;
    image_t *imgs;
    size_t   nimgs, cimgs;
};

pdf_t *pdf_new(const char *title, const char *author)
{
    pdf_t *p = xcalloc(1, sizeof *p);
    p->title = xstrdup(title ? title : "");
    p->author = xstrdup(author ? author : "");
    p->cur = -1;
    return p;
}

void pdf_free(pdf_t *p)
{
    if (!p) return;
    for (size_t i = 0; i < p->npages; i++) { sb_free(&p->pages[i].content); free(p->pages[i].links); }
    for (size_t i = 0; i < p->nimgs; i++) free(p->imgs[i].z);
    free(p->pages);
    free(p->imgs);
    free(p->title);
    free(p->author);
    free(p);
}

int pdf_page_new(pdf_t *p)
{
    VEC_RESERVE(p->pages, p->cpages, p->npages + 1);
    memset(&p->pages[p->npages], 0, sizeof(page_t));
    p->cur = (int)p->npages++;
    return p->cur;
}

int pdf_page_count(const pdf_t *p) { return (int)p->npages; }
void pdf_set_page(pdf_t *p, int idx) { if (idx >= 0 && (size_t)idx < p->npages) p->cur = idx; }

static sbuf_t *cs(pdf_t *p)
{
    if (p->cur < 0) pdf_page_new(p);
    return &p->pages[p->cur].content;
}

static void color_op(sbuf_t *s, rgb_t c, const char *op)
{
    sb_printf(s, "%.3f %.3f %.3f %s\n", ((c >> 16) & 0xFF) / 255.0, ((c >> 8) & 0xFF) / 255.0, (c & 0xFF) / 255.0, op);
}

void pdf_text(pdf_t *p, double x, double y, pdf_font_t f, double size, rgb_t col, const char *utf8)
{
    uint8_t buf[2048];
    size_t n = encode_text(utf8, buf, sizeof buf);
    sbuf_t *s = cs(p);
    sb_printf(s, "BT /F%d %.2f Tf ", (int)f + 1, size);
    color_op(s, col, "rg");
    sb_printf(s, "%.2f %.2f Td (", x, PDF_A4_H - y);
    for (size_t i = 0; i < n; i++) {
        uint8_t b = buf[i];
        if (b == '(' || b == ')' || b == '\\') { char e[2] = {'\\', (char)b}; sb_append(s, e, 2); }
        else if (b < 32 || b > 126) sb_printf(s, "\\%03o", b);
        else sb_append(s, &b, 1);
    }
    sb_printf(s, ") Tj ET\n");
}

void pdf_rect(pdf_t *p, double x, double y, double w, double h, rgb_t fill)
{
    sbuf_t *s = cs(p);
    color_op(s, fill, "rg");
    sb_printf(s, "%.2f %.2f %.2f %.2f re f\n", x, PDF_A4_H - y - h, w, h);
}

void pdf_rect_stroke(pdf_t *p, double x, double y, double w, double h, double lw, rgb_t col)
{
    sbuf_t *s = cs(p);
    color_op(s, col, "RG");
    sb_printf(s, "%.2f w %.2f %.2f %.2f %.2f re S\n", lw, x, PDF_A4_H - y - h, w, h);
}

void pdf_line(pdf_t *p, double x0, double y0, double x1, double y1, double lw, rgb_t col)
{
    sbuf_t *s = cs(p);
    color_op(s, col, "RG");
    sb_printf(s, "%.2f w %.2f %.2f m %.2f %.2f l S\n", lw, x0, PDF_A4_H - y0, x1, PDF_A4_H - y1);
}

void pdf_link(pdf_t *p, double x, double y, double w, double h, int target)
{
    if (p->cur < 0) return;
    page_t *pg = &p->pages[p->cur];
    VEC_RESERVE(pg->links, pg->clinks, pg->nlinks + 1);
    pg->links[pg->nlinks++] = (link_t){x, y, w, h, target};
}

int pdf_image_add(pdf_t *p, const canvas_t *c)
{
    size_t raw = (size_t)c->w * (size_t)c->h * 3;
    uLongf zl = compressBound((uLong)raw);
    uint8_t *z = xmalloc(zl);
    if (compress2(z, &zl, c->px, (uLong)raw, 6) != Z_OK) { free(z); return -1; }
    VEC_RESERVE(p->imgs, p->cimgs, p->nimgs + 1);
    p->imgs[p->nimgs] = (image_t){c->w, c->h, z, (size_t)zl};
    return (int)p->nimgs++;
}

void pdf_image_draw(pdf_t *p, int id, double x, double y, double w, double h)
{
    if (id < 0) return;
    sbuf_t *s = cs(p);
    sb_printf(s, "q %.2f 0 0 %.2f %.2f %.2f cm /Im%d Do Q\n", w, h, x, PDF_A4_H - y - h, id);
}

/* ------------------------------------------------------------------ output */

typedef struct {
    FILE    *f;
    long     pos;
    long    *offs;
    size_t   noffs;
    int      err;
} writer_t;

static void w_raw(writer_t *w, const void *d, size_t n)
{
    if (fwrite(d, 1, n, w->f) != n) w->err = 1;
    w->pos += (long)n;
}

static void w_printf(writer_t *w, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;
static void w_printf(writer_t *w, const char *fmt, ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > 0) w_raw(w, buf, (size_t)MIN((size_t)n, sizeof buf - 1));
}

static void w_obj(writer_t *w, int num) { w->offs[num] = w->pos; w_printf(w, "%d 0 obj\n", num); }

/* UTF-16BE hex string for document info */
static void w_textstring(writer_t *w, const char *s)
{
    w_printf(w, "<FEFF");
    const uint8_t *p = (const uint8_t *)s;
    while (*p) {
        uint32_t cp;
        if (p[0] < 0x80) cp = *p++;
        else if ((p[0] & 0xE0) == 0xC0 && p[1]) { cp = ((uint32_t)(p[0] & 0x1F) << 6) | (p[1] & 0x3F); p += 2; }
        else if ((p[0] & 0xF0) == 0xE0 && p[1] && p[2]) {
            cp = ((uint32_t)(p[0] & 0x0F) << 12) | ((uint32_t)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
            p += 3;
        } else { cp = '?'; p++; }
        w_printf(w, "%04X", (unsigned)(cp & 0xFFFF));
    }
    w_printf(w, ">");
}

int pdf_save(pdf_t *p, const char *path)
{
    writer_t w = {0};
    w.f = fopen(path, "wb");
    if (!w.f) return -1;

    /* object numbering */
    enum { O_CATALOG = 1, O_PAGES, O_F1, O_F2, O_F3, O_INFO, O_ENC, O_FIRST_FREE };
    int img_base = O_FIRST_FREE;
    int page_base = img_base + (int)p->nimgs;
    int total = page_base + 2 * (int)p->npages;
    w.offs = xcalloc((size_t)total + 1, sizeof(long));
    w.noffs = (size_t)total;

    w_printf(&w, "%%PDF-1.4\n%%\xE2\xE3\xCF\xD3\n");

    w_obj(&w, O_CATALOG);
    w_printf(&w, "<< /Type /Catalog /Pages %d 0 R /PageMode /UseNone >>\nendobj\n", O_PAGES);

    w_obj(&w, O_PAGES);
    w_printf(&w, "<< /Type /Pages /Count %zu /Kids [", p->npages);
    for (size_t i = 0; i < p->npages; i++) w_printf(&w, "%d 0 R ", page_base + 2 * (int)i);
    w_printf(&w, "] >>\nendobj\n");

    static const char *fonts[3] = {"Helvetica", "Helvetica-Bold", "Courier"};
    for (int i = 0; i < 3; i++) {
        w_obj(&w, O_F1 + i);
        w_printf(&w, "<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding %d 0 R >>\nendobj\n", fonts[i], O_ENC);
    }

    w_obj(&w, O_INFO);
    {
        time_t now = time(NULL);
        struct tm *tm = gmtime(&now);
        char date[32] = "";
        if (tm) strftime(date, sizeof date, "D:%Y%m%d%H%M%SZ", tm);
        w_printf(&w, "<< /Title ");
        w_textstring(&w, p->title);
        w_printf(&w, " /Author ");
        w_textstring(&w, p->author);
        w_printf(&w, " /Producer (%s %s) /CreationDate (%s) >>\nendobj\n", TOOL_NAME, TOOL_VERSION, date);
    }

    w_obj(&w, O_ENC);
    w_printf(&w, "<< /Type /Encoding /BaseEncoding /WinAnsiEncoding /Differences %s >>\nendobj\n", DIFFERENCES);

    for (size_t i = 0; i < p->nimgs; i++) {
        image_t *im = &p->imgs[i];
        w_obj(&w, img_base + (int)i);
        w_printf(&w,
                 "<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB "
                 "/BitsPerComponent 8 /Filter /FlateDecode /Length %zu >>\nstream\n",
                 im->w, im->h, im->zlen);
        w_raw(&w, im->z, im->zlen);
        w_printf(&w, "\nendstream\nendobj\n");
    }

    for (size_t i = 0; i < p->npages; i++) {
        page_t *pg = &p->pages[i];
        int po = page_base + 2 * (int)i;
        w_obj(&w, po);
        w_printf(&w,
                 "<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.2f %.2f] /Contents %d 0 R\n"
                 "/Resources << /Font << /F1 %d 0 R /F2 %d 0 R /F3 %d 0 R >>",
                 O_PAGES, PDF_A4_W, PDF_A4_H, po + 1, O_F1, O_F2, O_F3);
        if (p->nimgs) {
            w_printf(&w, " /XObject <<");
            for (size_t k = 0; k < p->nimgs; k++) w_printf(&w, " /Im%zu %d 0 R", k, img_base + (int)k);
            w_printf(&w, " >>");
        }
        w_printf(&w, " /ProcSet [/PDF /Text /ImageC] >>");
        if (pg->nlinks) {
            w_printf(&w, "\n/Annots [");
            for (size_t k = 0; k < pg->nlinks; k++) {
                link_t *l = &pg->links[k];
                if (l->target < 0 || (size_t)l->target >= p->npages) continue;
                w_printf(&w,
                         "<< /Type /Annot /Subtype /Link /Rect [%.2f %.2f %.2f %.2f] /Border [0 0 0] "
                         "/Dest [%d 0 R /XYZ null null null] >> ",
                         l->x, PDF_A4_H - l->y - l->h, l->x + l->w, PDF_A4_H - l->y, page_base + 2 * l->target);
            }
            w_printf(&w, "]");
        }
        w_printf(&w, " >>\nendobj\n");

        uLongf zl = compressBound((uLong)pg->content.len);
        uint8_t *z = xmalloc(zl);
        if (compress2(z, &zl, (const Bytef *)(pg->content.data ? pg->content.data : ""), (uLong)pg->content.len, 6) != Z_OK)
            w.err = 1;
        w_obj(&w, po + 1);
        w_printf(&w, "<< /Length %lu /Filter /FlateDecode >>\nstream\n", (unsigned long)zl);
        w_raw(&w, z, zl);
        w_printf(&w, "\nendstream\nendobj\n");
        free(z);
    }

    long xref = w.pos;
    w_printf(&w, "xref\n0 %d\n0000000000 65535 f \n", total);
    for (int i = 1; i < total; i++) w_printf(&w, "%010ld 00000 n \n", w.offs[i]);
    w_printf(&w, "trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%ld\n%%%%EOF\n", total, O_CATALOG,
             O_INFO, xref);

    free(w.offs);
    int rc = w.err ? -1 : 0;
    if (fclose(w.f) != 0) rc = -1;
    return rc;
}
