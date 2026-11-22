/* png.h - writes an RGB canvas as a PNG file (zlib for DEFLATE + CRC). */
#ifndef PNG_H
#define PNG_H

#include "raster.h"

int png_write(const char *path, const canvas_t *c);

#endif
