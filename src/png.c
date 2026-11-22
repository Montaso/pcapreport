#include "png.h"
#include "common.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int write_chunk(FILE *f, const char *type, const uint8_t *data, uint32_t len)
{
    uint8_t hdr[8];
    put32(hdr, len);
    memcpy(hdr + 4, type, 4);
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef *)type, 4);
    if (len) crc = crc32(crc, data, len);
    uint8_t tail[4];
    put32(tail, (uint32_t)crc);
    if (fwrite(hdr, 1, 8, f) != 8) return -1;
    if (len && fwrite(data, 1, len, f) != len) return -1;
    if (fwrite(tail, 1, 4, f) != 4) return -1;
    return 0;
}

int png_write(const char *path, const canvas_t *c)
{
    size_t stride = (size_t)c->w * 3;
    size_t rawlen = (stride + 1) * (size_t)c->h;
    uint8_t *raw = xmalloc(rawlen);

    /* filter type 1 (Sub) on every row: good for flat chart colours */
    for (int y = 0; y < c->h; y++) {
        uint8_t *dst = raw + (size_t)y * (stride + 1);
        const uint8_t *src = c->px + (size_t)y * stride;
        dst[0] = 1;
        for (size_t i = 0; i < stride; i++)
            dst[1 + i] = (uint8_t)(src[i] - (i >= 3 ? src[i - 3] : 0));
    }

    uLongf zlen = compressBound((uLong)rawlen);
    uint8_t *z = xmalloc(zlen);
    if (compress2(z, &zlen, raw, (uLong)rawlen, 9) != Z_OK) {
        free(raw);
        free(z);
        return -1;
    }
    free(raw);

    FILE *f = fopen(path, "wb");
    if (!f) { free(z); return -1; }
    static const uint8_t sig[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    uint8_t ihdr[13];
    put32(ihdr, (uint32_t)c->w);
    put32(ihdr + 4, (uint32_t)c->h);
    ihdr[8] = 8;  /* bit depth */
    ihdr[9] = 2;  /* colour type: truecolour */
    ihdr[10] = 0; /* deflate */
    ihdr[11] = 0; /* adaptive filtering */
    ihdr[12] = 0; /* no interlace */
    static const char sw[] = "Software\0" TOOL_NAME " " TOOL_VERSION;
    int rc = 0;
    if (fwrite(sig, 1, 8, f) != 8) rc = -1;
    if (!rc) rc = write_chunk(f, "IHDR", ihdr, 13);
    if (!rc) rc = write_chunk(f, "tEXt", (const uint8_t *)sw, (uint32_t)(sizeof sw - 1));
    if (!rc) rc = write_chunk(f, "IDAT", z, (uint32_t)zlen);
    if (!rc) rc = write_chunk(f, "IEND", NULL, 0);
    if (fclose(f) != 0) rc = -1;
    free(z);
    return rc;
}
