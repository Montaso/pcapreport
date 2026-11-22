#include "raster.h"
#include "common.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ font
 * 5 columns x 9 rows: rows 0..6 = cap height, rows 7..8 = descender.
 * Each glyph is a '|' separated list of rows; missing rows are blank.   */

typedef struct {
    uint32_t    cp;
    const char *rows;
} glyph_src_t;

static const glyph_src_t GLYPHS[] = {
    {' ', ""},
    {'!', "..#..|..#..|..#..|..#..|..#..|.....|..#.."},
    {'"', ".#.#.|.#.#.|.#.#."},
    {'#', ".#.#.|.#.#.|#####|.#.#.|#####|.#.#.|.#.#."},
    {'$', "..#..|.####|#.#..|.###.|..#.#|####.|..#.."},
    {'%', "##...|##..#|...#.|..#..|.#...|#..##|...##"},
    {'&', ".##..|#..#.|#.#..|.#...|#.#.#|#..#.|.##.#"},
    {'\'', "..#..|..#..|.#..."},
    {'(', "...#.|..#..|.#...|.#...|.#...|..#..|...#."},
    {')', ".#...|..#..|...#.|...#.|...#.|..#..|.#..."},
    {'*', ".....|..#..|#.#.#|.###.|#.#.#|..#..|....."},
    {'+', ".....|..#..|..#..|#####|..#..|..#..|....."},
    {',', ".....|.....|.....|.....|.....|..#..|..#..|.#..."},
    {'-', ".....|.....|.....|#####|.....|.....|....."},
    {'.', ".....|.....|.....|.....|.....|.##..|.##.."},
    {'/', ".....|....#|...#.|..#..|.#...|#....|....."},
    {'0', ".###.|#...#|#..##|#.#.#|##..#|#...#|.###."},
    {'1', "..#..|.##..|..#..|..#..|..#..|..#..|.###."},
    {'2', ".###.|#...#|....#|...#.|..#..|.#...|#####"},
    {'3', "#####|...#.|..#..|...#.|....#|#...#|.###."},
    {'4', "...#.|..##.|.#.#.|#..#.|#####|...#.|...#."},
    {'5', "#####|#....|####.|....#|....#|#...#|.###."},
    {'6', "..##.|.#...|#....|####.|#...#|#...#|.###."},
    {'7', "#####|....#|...#.|..#..|.#...|.#...|.#..."},
    {'8', ".###.|#...#|#...#|.###.|#...#|#...#|.###."},
    {'9', ".###.|#...#|#...#|.####|....#|...#.|.##.."},
    {':', ".....|.##..|.##..|.....|.##..|.##..|....."},
    {';', ".....|.##..|.##..|.....|.##..|.##..|.#..."},
    {'<', "...#.|..#..|.#...|#....|.#...|..#..|...#."},
    {'=', ".....|.....|#####|.....|#####|.....|....."},
    {'>', ".#...|..#..|...#.|....#|...#.|..#..|.#..."},
    {'?', ".###.|#...#|....#|...#.|..#..|.....|..#.."},
    {'@', ".###.|#...#|....#|.##.#|#.#.#|#.#.#|.###."},
    {'A', ".###.|#...#|#...#|#####|#...#|#...#|#...#"},
    {'B', "####.|#...#|#...#|####.|#...#|#...#|####."},
    {'C', ".###.|#...#|#....|#....|#....|#...#|.###."},
    {'D', "###..|#..#.|#...#|#...#|#...#|#..#.|###.."},
    {'E', "#####|#....|#....|####.|#....|#....|#####"},
    {'F', "#####|#....|#....|####.|#....|#....|#...."},
    {'G', ".###.|#...#|#....|#.###|#...#|#...#|.####"},
    {'H', "#...#|#...#|#...#|#####|#...#|#...#|#...#"},
    {'I', ".###.|..#..|..#..|..#..|..#..|..#..|.###."},
    {'J', "..###|...#.|...#.|...#.|...#.|#..#.|.##.."},
    {'K', "#...#|#..#.|#.#..|##...|#.#..|#..#.|#...#"},
    {'L', "#....|#....|#....|#....|#....|#....|#####"},
    {'M', "#...#|##.##|#.#.#|#.#.#|#...#|#...#|#...#"},
    {'N', "#...#|#...#|##..#|#.#.#|#..##|#...#|#...#"},
    {'O', ".###.|#...#|#...#|#...#|#...#|#...#|.###."},
    {'P', "####.|#...#|#...#|####.|#....|#....|#...."},
    {'Q', ".###.|#...#|#...#|#...#|#.#.#|#..#.|.##.#"},
    {'R', "####.|#...#|#...#|####.|#.#..|#..#.|#...#"},
    {'S', ".####|#....|#....|.###.|....#|....#|####."},
    {'T', "#####|..#..|..#..|..#..|..#..|..#..|..#.."},
    {'U', "#...#|#...#|#...#|#...#|#...#|#...#|.###."},
    {'V', "#...#|#...#|#...#|#...#|#...#|.#.#.|..#.."},
    {'W', "#...#|#...#|#...#|#.#.#|#.#.#|#.#.#|.#.#."},
    {'X', "#...#|#...#|.#.#.|..#..|.#.#.|#...#|#...#"},
    {'Y', "#...#|#...#|.#.#.|..#..|..#..|..#..|..#.."},
    {'Z', "#####|....#|...#.|..#..|.#...|#....|#####"},
    {'[', ".###.|.#...|.#...|.#...|.#...|.#...|.###."},
    {'\\', ".....|#....|.#...|..#..|...#.|....#|....."},
    {']', ".###.|...#.|...#.|...#.|...#.|...#.|.###."},
    {'^', "..#..|.#.#.|#...#"},
    {'_', ".....|.....|.....|.....|.....|.....|.....|#####"},
    {'`', ".#...|..#..|...#."},
    {'a', ".....|.....|.###.|....#|.####|#...#|.####"},
    {'b', "#....|#....|#.##.|##..#|#...#|#...#|####."},
    {'c', ".....|.....|.###.|#....|#....|#...#|.###."},
    {'d', "....#|....#|.##.#|#..##|#...#|#...#|.####"},
    {'e', ".....|.....|.###.|#...#|#####|#....|.###."},
    {'f', "..##.|.#..#|.#...|###..|.#...|.#...|.#..."},
    {'g', ".....|.....|.####|#...#|#...#|#...#|.####|....#|.###."},
    {'h', "#....|#....|#.##.|##..#|#...#|#...#|#...#"},
    {'i', "..#..|.....|.##..|..#..|..#..|..#..|.###."},
    {'j', "...#.|.....|..##.|...#.|...#.|...#.|...#.|#..#.|.##.."},
    {'k', "#....|#....|#..#.|#.#..|##...|#.#..|#..#."},
    {'l', ".##..|..#..|..#..|..#..|..#..|..#..|.###."},
    {'m', ".....|.....|##.#.|#.#.#|#.#.#|#.#.#|#.#.#"},
    {'n', ".....|.....|#.##.|##..#|#...#|#...#|#...#"},
    {'o', ".....|.....|.###.|#...#|#...#|#...#|.###."},
    {'p', ".....|.....|####.|#...#|#...#|#...#|####.|#....|#...."},
    {'q', ".....|.....|.####|#...#|#...#|#...#|.####|....#|....#"},
    {'r', ".....|.....|#.##.|##..#|#....|#....|#...."},
    {'s', ".....|.....|.####|#....|.###.|....#|####."},
    {'t', ".#...|.#...|###..|.#...|.#...|.#..#|..##."},
    {'u', ".....|.....|#...#|#...#|#...#|#..##|.##.#"},
    {'v', ".....|.....|#...#|#...#|#...#|.#.#.|..#.."},
    {'w', ".....|.....|#...#|#...#|#.#.#|#.#.#|.#.#."},
    {'x', ".....|.....|#...#|.#.#.|..#..|.#.#.|#...#"},
    {'y', ".....|.....|#...#|#...#|#...#|#...#|.####|....#|.###."},
    {'z', ".....|.....|#####|...#.|..#..|.#...|#####"},
    {'{', "...#.|..#..|..#..|.#...|..#..|..#..|...#."},
    {'|', "..#..|..#..|..#..|..#..|..#..|..#..|..#.."},
    {'}', ".#...|..#..|..#..|...#.|..#..|..#..|.#..."},
    {'~', ".....|.....|.#...|#.#.#|...#.|.....|....."},
    /* Polish diacritics */
    {0x0105, ".....|.....|.###.|....#|.####|#...#|.####|...#.|....#"}, /* ą */
    {0x0107, "...#.|..#..|.###.|#....|#....|#...#|.###."},             /* ć */
    {0x0119, ".....|.....|.###.|#...#|#####|#....|.###.|..#..|...##"}, /* ę */
    {0x0142, ".##..|..#..|..##.|.##..|..#..|..#..|.###."},             /* ł */
    {0x0144, "...#.|..#..|#.##.|##..#|#...#|#...#|#...#"},             /* ń */
    {0x00F3, "...#.|..#..|.###.|#...#|#...#|#...#|.###."},             /* ó */
    {0x015B, "...#.|..#..|.####|#....|.###.|....#|####."},             /* ś */
    {0x017A, "...#.|..#..|#####|...#.|..#..|.#...|#####"},             /* ź */
    {0x017C, "..#..|.....|#####|...#.|..#..|.#...|#####"},             /* ż */
    {0x0104, ".###.|#...#|#...#|#####|#...#|#...#|#...#|...#.|....#"}, /* Ą */
    {0x0106, "..##.|.#..#|#....|#....|#....|#...#|.###."},             /* Ć */
    {0x0118, "#####|#....|#....|####.|#....|#....|#####|...#.|....#"}, /* Ę */
    {0x0141, "#....|#....|#.#..|##...|#....|#....|#####"},             /* Ł */
    {0x0143, "..#..|#...#|##..#|#.#.#|#..##|#...#|#...#"},             /* Ń */
    {0x00D3, "..#..|.###.|#...#|#...#|#...#|#...#|.###."},             /* Ó */
    {0x015A, "..#..|.####|#....|.###.|....#|....#|####."},             /* Ś */
    {0x0179, "..#..|#####|...#.|..#..|.#...|#....|#####"},             /* Ź */
    {0x017B, "..#..|#####|...#.|..#..|.#...|#....|#####"},             /* Ż */
    {0x00B5, ".....|.....|#...#|#...#|#...#|##.##|#.#.#|#....|#...."}, /* µ */
    {0x00B0, ".##..|#..#.|.##.."},                                     /* ° */
    {0x2192, ".....|..#..|...#.|#####|...#.|..#..|....."},             /* → */
};

#define GLYPH_ROWS 9
typedef struct { uint32_t cp; uint8_t rows[GLYPH_ROWS]; } glyph_t;
static glyph_t g_font[ARRAY_LEN(GLYPHS)];
static int g_font_ready = 0;

static void font_init(void)
{
    if (g_font_ready) return;
    for (size_t i = 0; i < ARRAY_LEN(GLYPHS); i++) {
        g_font[i].cp = GLYPHS[i].cp;
        memset(g_font[i].rows, 0, GLYPH_ROWS);
        const char *s = GLYPHS[i].rows;
        int r = 0, col = 0;
        for (; *s && r < GLYPH_ROWS; s++) {
            if (*s == '|') { r++; col = 0; continue; }
            if (*s == '#' && col < 5) g_font[i].rows[r] |= (uint8_t)(0x10 >> col);
            col++;
        }
    }
    g_font_ready = 1;
}

static const glyph_t *glyph(uint32_t cp)
{
    font_init();
    for (size_t i = 0; i < ARRAY_LEN(g_font); i++)
        if (g_font[i].cp == cp) return &g_font[i];
    /* fallback: '?' */
    for (size_t i = 0; i < ARRAY_LEN(g_font); i++)
        if (g_font[i].cp == '?') return &g_font[i];
    return &g_font[0];
}

static uint32_t utf8_next(const char **ps)
{
    const uint8_t *s = (const uint8_t *)*ps;
    uint32_t cp;
    int n;
    if (s[0] < 0x80) { cp = s[0]; n = 1; }
    else if ((s[0] & 0xE0) == 0xC0 && s[1]) { cp = ((uint32_t)(s[0] & 0x1F) << 6) | (s[1] & 0x3F); n = 2; }
    else if ((s[0] & 0xF0) == 0xE0 && s[1] && s[2]) {
        cp = ((uint32_t)(s[0] & 0x0F) << 12) | ((uint32_t)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        n = 3;
    } else { cp = '?'; n = 1; }
    *ps += n;
    return cp;
}

/* ------------------------------------------------------------------ canvas */

canvas_t *cv_new(int w, int h, rgb_t bg)
{
    canvas_t *c = xmalloc(sizeof *c);
    c->w = w;
    c->h = h;
    c->px = xmalloc((size_t)w * (size_t)h * 3);
    cv_fill_rect(c, 0, 0, w, h, bg);
    return c;
}

void cv_free(canvas_t *c)
{
    if (!c) return;
    free(c->px);
    free(c);
}

void cv_pixel(canvas_t *c, int x, int y, rgb_t col)
{
    if (x < 0 || y < 0 || x >= c->w || y >= c->h) return;
    uint8_t *p = c->px + ((size_t)y * (size_t)c->w + (size_t)x) * 3;
    p[0] = (uint8_t)(col >> 16);
    p[1] = (uint8_t)(col >> 8);
    p[2] = (uint8_t)col;
}

void cv_blend(canvas_t *c, int x, int y, rgb_t col, double a)
{
    if (x < 0 || y < 0 || x >= c->w || y >= c->h || a <= 0) return;
    if (a >= 1) { cv_pixel(c, x, y, col); return; }
    uint8_t *p = c->px + ((size_t)y * (size_t)c->w + (size_t)x) * 3;
    double r = (col >> 16) & 0xFF, g = (col >> 8) & 0xFF, b = col & 0xFF;
    p[0] = (uint8_t)(p[0] + (r - p[0]) * a + 0.5);
    p[1] = (uint8_t)(p[1] + (g - p[1]) * a + 0.5);
    p[2] = (uint8_t)(p[2] + (b - p[2]) * a + 0.5);
}

void cv_fill_rect(canvas_t *c, int x, int y, int w, int h, rgb_t col)
{
    int x0 = MAX(x, 0), y0 = MAX(y, 0);
    int x1 = MIN(x + w, c->w), y1 = MIN(y + h, c->h);
    for (int yy = y0; yy < y1; yy++)
        for (int xx = x0; xx < x1; xx++) cv_pixel(c, xx, yy, col);
}

void cv_fill_bar(canvas_t *c, int x, int y, int w, int h, int r, rgb_t col, int horizontal)
{
    if (w <= 0 || h <= 0) return;
    int lim = horizontal ? MIN(h / 2, w) : MIN(w / 2, h);
    if (r > lim) r = lim;
    for (int yy = 0; yy < h; yy++) {
        for (int xx = 0; xx < w; xx++) {
            double cov = 1.0;
            double dx = 0, dy = 0;
            int corner = 0;
            if (!horizontal && yy < r) {
                /* top-left / top-right */
                if (xx < r) { dx = r - (xx + 0.5); dy = r - (yy + 0.5); corner = 1; }
                else if (xx >= w - r) { dx = (xx + 0.5) - (w - r); dy = r - (yy + 0.5); corner = 1; }
            } else if (horizontal && xx >= w - r) {
                if (yy < r) { dx = (xx + 0.5) - (w - r); dy = r - (yy + 0.5); corner = 1; }
                else if (yy >= h - r) { dx = (xx + 0.5) - (w - r); dy = (yy + 0.5) - (h - r); corner = 1; }
            }
            if (corner) {
                double d = sqrt(dx * dx + dy * dy);
                cov = r + 0.5 - d;
                if (cov > 1) cov = 1;
            }
            cv_blend(c, x + xx, y + yy, col, cov);
        }
    }
}

void cv_hline(canvas_t *c, int x0, int x1, int y, rgb_t col)
{
    if (x0 > x1) { int t = x0; x0 = x1; x1 = t; }
    for (int x = x0; x <= x1; x++) cv_pixel(c, x, y, col);
}

void cv_vline(canvas_t *c, int x, int y0, int y1, rgb_t col)
{
    if (y0 > y1) { int t = y0; y0 = y1; y1 = t; }
    for (int y = y0; y <= y1; y++) cv_pixel(c, x, y, col);
}

void cv_line(canvas_t *c, double x0, double y0, double x1, double y1, double width, rgb_t col)
{
    double hw = width / 2.0;
    int bx0 = (int)floor(MIN(x0, x1) - hw - 1), bx1 = (int)ceil(MAX(x0, x1) + hw + 1);
    int by0 = (int)floor(MIN(y0, y1) - hw - 1), by1 = (int)ceil(MAX(y0, y1) + hw + 1);
    double dx = x1 - x0, dy = y1 - y0;
    double len2 = dx * dx + dy * dy;
    for (int y = MAX(by0, 0); y <= MIN(by1, c->h - 1); y++) {
        for (int x = MAX(bx0, 0); x <= MIN(bx1, c->w - 1); x++) {
            double px = x + 0.5, py = y + 0.5;
            double t = len2 > 0 ? ((px - x0) * dx + (py - y0) * dy) / len2 : 0;
            if (t < 0) t = 0;
            if (t > 1) t = 1;
            double qx = x0 + t * dx - px, qy = y0 + t * dy - py;
            double d = sqrt(qx * qx + qy * qy);
            double cov = hw + 0.5 - d;
            if (cov <= 0) continue;
            if (cov > 1) cov = 1;
            cv_blend(c, x, y, col, cov);
        }
    }
}

void cv_fill_circle(canvas_t *c, double cx, double cy, double r, rgb_t col)
{
    for (int y = (int)floor(cy - r - 1); y <= (int)ceil(cy + r + 1); y++)
        for (int x = (int)floor(cx - r - 1); x <= (int)ceil(cx + r + 1); x++) {
            double d = hypot(x + 0.5 - cx, y + 0.5 - cy);
            double cov = r + 0.5 - d;
            if (cov > 0) cv_blend(c, x, y, col, cov > 1 ? 1 : cov);
        }
}

void cv_ring_sector(canvas_t *c, double cx, double cy, double r0, double r1, double a0, double a1, rgb_t col)
{
    const double TAU = 6.283185307179586;
    for (int y = (int)floor(cy - r1 - 1); y <= (int)ceil(cy + r1 + 1); y++)
        for (int x = (int)floor(cx - r1 - 1); x <= (int)ceil(cx + r1 + 1); x++) {
            double dx = x + 0.5 - cx, dy = y + 0.5 - cy;
            double d = hypot(dx, dy);
            double cov = MIN(r1 + 0.5 - d, d - r0 + 0.5);
            if (cov <= 0) continue;
            double ang = atan2(dx, -dy);
            if (ang < 0) ang += TAU;
            double e0 = (ang - a0) * d, e1 = (a1 - ang) * d;   /* arc distance in px */
            double ca = MIN(e0, e1) + 0.5;
            if (ca <= 0) continue;
            cov = MIN(cov, ca);
            cv_blend(c, x, y, col, cov > 1 ? 1 : cov);
        }
}

void cv_fill_area(canvas_t *c, const double *xs, const double *ys, int n, double base, rgb_t col, double alpha)
{
    for (int k = 0; k + 1 < n; k++) {
        int xa = (int)floor(xs[k]), xb = (int)ceil(xs[k + 1]);
        for (int x = xa; x < xb; x++) {
            double t = xs[k + 1] > xs[k] ? (x + 0.5 - xs[k]) / (xs[k + 1] - xs[k]) : 0;
            if (t < 0 || t > 1) continue;
            double y = ys[k] + t * (ys[k + 1] - ys[k]);
            for (int yy = (int)ceil(y); yy < (int)base; yy++) cv_blend(c, x, yy, col, alpha);
        }
    }
}

/* ------------------------------------------------------------------ text */

int cv_text_width(const char *s, int scale)
{
    int n = 0;
    while (*s) { utf8_next(&s); n++; }
    return n ? (n * 6 - 1) * scale : 0;
}

int cv_text_height(int scale) { return 9 * scale; }

void cv_text(canvas_t *c, int x, int y, const char *s, rgb_t col, int scale)
{
    while (*s) {
        const glyph_t *g = glyph(utf8_next(&s));
        for (int r = 0; r < GLYPH_ROWS; r++)
            for (int k = 0; k < 5; k++)
                if (g->rows[r] & (0x10 >> k))
                    cv_fill_rect(c, x + k * scale, y + r * scale, scale, scale, col);
        x += 6 * scale;
    }
}

void cv_text_vert(canvas_t *c, int x, int y, const char *s, rgb_t col, int scale)
{
    /* glyph column k -> vertical offset upward, glyph row r -> x offset */
    while (*s) {
        const glyph_t *g = glyph(utf8_next(&s));
        for (int r = 0; r < GLYPH_ROWS; r++)
            for (int k = 0; k < 5; k++)
                if (g->rows[r] & (0x10 >> k))
                    cv_fill_rect(c, x + r * scale, y - (k + 1) * scale, scale, scale, col);
        y -= 6 * scale;
    }
}
