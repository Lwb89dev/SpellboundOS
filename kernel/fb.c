/* Freestanding RGB565 2D framebuffer and compact 5x7 ASCII font renderer. */
#include "fb.h"
#include <stddef.h>

/* Compact 5x7 column-major ASCII font (0x20..0x7E, LSB = top row). */
static const uint8_t fb_font5x7[95][5] = {
    {0x00,0x00,0x00,0x00,0x00}, /* ' ' */
    {0x00,0x00,0x5F,0x00,0x00}, /* '!' */
    {0x00,0x07,0x00,0x07,0x00}, /* '"' */
    {0x14,0x7F,0x14,0x7F,0x14}, /* '#' */
    {0x24,0x2A,0x7F,0x2A,0x12}, /* '$' */
    {0x23,0x13,0x08,0x64,0x62}, /* '%' */
    {0x36,0x49,0x55,0x22,0x50}, /* '&' */
    {0x00,0x05,0x03,0x00,0x00}, /* ''' */
    {0x00,0x1C,0x22,0x41,0x00}, /* '(' */
    {0x00,0x41,0x22,0x1C,0x00}, /* ')' */
    {0x14,0x08,0x3E,0x08,0x14}, /* '*' */
    {0x08,0x08,0x3E,0x08,0x08}, /* '+' */
    {0x00,0x50,0x30,0x00,0x00}, /* ',' */
    {0x08,0x08,0x08,0x08,0x08}, /* '-' */
    {0x00,0x60,0x60,0x00,0x00}, /* '.' */
    {0x20,0x10,0x08,0x04,0x02}, /* '/' */
    {0x3E,0x51,0x49,0x45,0x3E}, /* '0' */
    {0x00,0x42,0x7F,0x40,0x00}, /* '1' */
    {0x42,0x61,0x51,0x49,0x46}, /* '2' */
    {0x21,0x41,0x45,0x4B,0x31}, /* '3' */
    {0x18,0x14,0x12,0x7F,0x10}, /* '4' */
    {0x27,0x45,0x45,0x45,0x39}, /* '5' */
    {0x3C,0x4A,0x49,0x49,0x30}, /* '6' */
    {0x01,0x71,0x09,0x05,0x03}, /* '7' */
    {0x36,0x49,0x49,0x49,0x36}, /* '8' */
    {0x06,0x49,0x49,0x29,0x1E}, /* '9' */
    {0x00,0x36,0x36,0x00,0x00}, /* ':' */
    {0x00,0x56,0x36,0x00,0x00}, /* ';' */
    {0x08,0x14,0x22,0x41,0x00}, /* '<' */
    {0x14,0x14,0x14,0x14,0x14}, /* '=' */
    {0x00,0x41,0x22,0x14,0x08}, /* '>' */
    {0x02,0x01,0x51,0x09,0x06}, /* '?' */
    {0x32,0x49,0x79,0x41,0x3E}, /* '@' */
    {0x7E,0x11,0x11,0x11,0x7E}, /* 'A' */
    {0x7F,0x49,0x49,0x49,0x36}, /* 'B' */
    {0x3E,0x41,0x41,0x41,0x22}, /* 'C' */
    {0x7F,0x41,0x41,0x22,0x1C}, /* 'D' */
    {0x7F,0x49,0x49,0x49,0x41}, /* 'E' */
    {0x7F,0x09,0x09,0x09,0x01}, /* 'F' */
    {0x3E,0x41,0x49,0x49,0x7A}, /* 'G' */
    {0x7F,0x08,0x08,0x08,0x7F}, /* 'H' */
    {0x00,0x41,0x7F,0x41,0x00}, /* 'I' */
    {0x20,0x40,0x41,0x3F,0x01}, /* 'J' */
    {0x7F,0x08,0x14,0x22,0x41}, /* 'K' */
    {0x7F,0x40,0x40,0x40,0x40}, /* 'L' */
    {0x7F,0x02,0x0C,0x02,0x7F}, /* 'M' */
    {0x7F,0x04,0x08,0x10,0x7F}, /* 'N' */
    {0x3E,0x41,0x41,0x41,0x3E}, /* 'O' */
    {0x7F,0x09,0x09,0x09,0x06}, /* 'P' */
    {0x3E,0x41,0x51,0x21,0x5E}, /* 'Q' */
    {0x7F,0x09,0x19,0x29,0x46}, /* 'R' */
    {0x46,0x49,0x49,0x49,0x31}, /* 'S' */
    {0x01,0x01,0x7F,0x01,0x01}, /* 'T' */
    {0x3F,0x40,0x40,0x40,0x3F}, /* 'U' */
    {0x1F,0x20,0x40,0x20,0x1F}, /* 'V' */
    {0x3F,0x40,0x38,0x40,0x3F}, /* 'W' */
    {0x63,0x14,0x08,0x14,0x63}, /* 'X' */
    {0x07,0x08,0x70,0x08,0x07}, /* 'Y' */
    {0x61,0x51,0x49,0x45,0x43}, /* 'Z' */
    {0x00,0x7F,0x41,0x41,0x00}, /* '[' */
    {0x02,0x04,0x08,0x10,0x20}, /* '\' */
    {0x00,0x41,0x41,0x7F,0x00}, /* ']' */
    {0x04,0x02,0x01,0x02,0x04}, /* '^' */
    {0x40,0x40,0x40,0x40,0x40}, /* '_' */
    {0x00,0x01,0x02,0x04,0x00}, /* '`' */
    {0x20,0x54,0x54,0x54,0x78}, /* 'a' */
    {0x7F,0x48,0x44,0x44,0x38}, /* 'b' */
    {0x38,0x44,0x44,0x44,0x20}, /* 'c' */
    {0x38,0x44,0x44,0x48,0x7F}, /* 'd' */
    {0x38,0x54,0x54,0x54,0x18}, /* 'e' */
    {0x08,0x7E,0x09,0x01,0x02}, /* 'f' */
    {0x0C,0x52,0x52,0x52,0x3E}, /* 'g' */
    {0x7F,0x08,0x04,0x04,0x78}, /* 'h' */
    {0x00,0x44,0x7D,0x40,0x00}, /* 'i' */
    {0x20,0x40,0x44,0x3D,0x00}, /* 'j' */
    {0x7F,0x10,0x28,0x44,0x00}, /* 'k' */
    {0x00,0x41,0x7F,0x40,0x00}, /* 'l' */
    {0x7C,0x04,0x18,0x04,0x78}, /* 'm' */
    {0x7C,0x08,0x04,0x04,0x78}, /* 'n' */
    {0x38,0x44,0x44,0x44,0x38}, /* 'o' */
    {0x7C,0x14,0x14,0x14,0x08}, /* 'p' */
    {0x08,0x14,0x14,0x18,0x7C}, /* 'q' */
    {0x7C,0x08,0x04,0x04,0x08}, /* 'r' */
    {0x48,0x54,0x54,0x54,0x20}, /* 's' */
    {0x04,0x3F,0x44,0x40,0x20}, /* 't' */
    {0x3C,0x40,0x40,0x20,0x7C}, /* 'u' */
    {0x1C,0x20,0x40,0x20,0x1C}, /* 'v' */
    {0x3C,0x40,0x30,0x40,0x3C}, /* 'w' */
    {0x44,0x28,0x10,0x28,0x44}, /* 'x' */
    {0x0C,0x50,0x50,0x50,0x3C}, /* 'y' */
    {0x44,0x64,0x54,0x4C,0x44}, /* 'z' */
    {0x00,0x08,0x36,0x41,0x00}, /* '{' */
    {0x00,0x00,0x7F,0x00,0x00}, /* '|' */
    {0x00,0x41,0x36,0x08,0x00}, /* '}' */
    {0x10,0x08,0x08,0x10,0x08}, /* '~' */
};

int fb_init(struct fb *fb, uint16_t *pixels, uint16_t width, uint16_t height) {
    if (!fb || !pixels || width == 0 || height == 0) {
        return -1;
    }
    fb->pixels = pixels;
    fb->width = width;
    fb->height = height;
    fb->dirty = false;
    fb->dirty_rect = (struct fb_rect){0, 0, 0, 0};
    return 0;
}

void fb_mark_dirty(struct fb *fb, int32_t x0, int32_t y0, int32_t x1, int32_t y1) {
    if (!fb || !fb->pixels || fb->width == 0 || fb->height == 0) {
        return;
    }
    if (x0 > x1) { int32_t t = x0; x0 = x1; x1 = t; }
    if (y0 > y1) { int32_t t = y0; y0 = y1; y1 = t; }
    if (x1 < 0 || y1 < 0 || x0 >= fb->width || y0 >= fb->height) {
        return;
    }
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 >= fb->width) x1 = fb->width - 1;
    if (y1 >= fb->height) y1 = fb->height - 1;

    if (!fb->dirty) {
        fb->dirty = true;
        fb->dirty_rect.x0 = (uint16_t)x0;
        fb->dirty_rect.y0 = (uint16_t)y0;
        fb->dirty_rect.x1 = (uint16_t)x1;
        fb->dirty_rect.y1 = (uint16_t)y1;
    } else {
        if ((uint16_t)x0 < fb->dirty_rect.x0) fb->dirty_rect.x0 = (uint16_t)x0;
        if ((uint16_t)y0 < fb->dirty_rect.y0) fb->dirty_rect.y0 = (uint16_t)y0;
        if ((uint16_t)x1 > fb->dirty_rect.x1) fb->dirty_rect.x1 = (uint16_t)x1;
        if ((uint16_t)y1 > fb->dirty_rect.y1) fb->dirty_rect.y1 = (uint16_t)y1;
    }
}

void fb_clear_dirty(struct fb *fb) {
    if (fb) {
        fb->dirty = false;
    }
}

bool fb_get_dirty(const struct fb *fb, struct fb_rect *out) {
    if (!fb || !fb->dirty) {
        return false;
    }
    if (out) {
        *out = fb->dirty_rect;
    }
    return true;
}

static inline void fb_plot_raw(struct fb *fb, int32_t x, int32_t y, uint16_t color) {
    if (x >= 0 && y >= 0 && x < fb->width && y < fb->height) {
        fb->pixels[(uint32_t)y * fb->width + (uint32_t)x] = color;
    }
}

void fb_clear(struct fb *fb, uint16_t color) {
    if (!fb || !fb->pixels) {
        return;
    }
    uint32_t total = (uint32_t)fb->width * (uint32_t)fb->height;
    for (uint32_t i = 0; i < total; i++) {
        fb->pixels[i] = color;
    }
    fb_mark_dirty(fb, 0, 0, fb->width - 1, fb->height - 1);
}

void fb_put_pixel(struct fb *fb, int32_t x, int32_t y, uint16_t color) {
    if (!fb || !fb->pixels || x < 0 || y < 0 || x >= fb->width || y >= fb->height) {
        return;
    }
    fb->pixels[(uint32_t)y * fb->width + (uint32_t)x] = color;
    fb_mark_dirty(fb, x, y, x, y);
}

uint16_t fb_get_pixel(const struct fb *fb, int32_t x, int32_t y) {
    if (!fb || !fb->pixels || x < 0 || y < 0 || x >= fb->width || y >= fb->height) {
        return 0;
    }
    return fb->pixels[(uint32_t)y * fb->width + (uint32_t)x];
}

void fb_hline(struct fb *fb, int32_t x, int32_t y, int32_t len, uint16_t color) {
    if (!fb || !fb->pixels || len <= 0 || y < 0 || y >= fb->height) {
        return;
    }
    int32_t x0 = x < 0 ? 0 : x;
    int32_t x1 = x + len - 1;
    if (x1 >= fb->width) x1 = fb->width - 1;
    if (x0 > x1) return;
    uint16_t *row = &fb->pixels[(uint32_t)y * fb->width];
    for (int32_t cx = x0; cx <= x1; cx++) {
        row[cx] = color;
    }
    fb_mark_dirty(fb, x0, y, x1, y);
}

void fb_vline(struct fb *fb, int32_t x, int32_t y, int32_t len, uint16_t color) {
    if (!fb || !fb->pixels || len <= 0 || x < 0 || x >= fb->width) {
        return;
    }
    int32_t y0 = y < 0 ? 0 : y;
    int32_t y1 = y + len - 1;
    if (y1 >= fb->height) y1 = fb->height - 1;
    if (y0 > y1) return;
    for (int32_t cy = y0; cy <= y1; cy++) {
        fb->pixels[(uint32_t)cy * fb->width + (uint32_t)x] = color;
    }
    fb_mark_dirty(fb, x, y0, x, y1);
}

void fb_line(struct fb *fb, int32_t x0, int32_t y0, int32_t x1, int32_t y1, uint16_t color) {
    if (!fb || !fb->pixels) {
        return;
    }
    fb_mark_dirty(fb, x0, y0, x1, y1);
    int32_t dx = x1 >= x0 ? (x1 - x0) : (x0 - x1);
    int32_t dy = y1 >= y0 ? (y1 - y0) : (y0 - y1);
    int32_t sx = x0 < x1 ? 1 : -1;
    int32_t sy = y0 < y1 ? 1 : -1;
    int32_t err = dx - dy;

    for (;;) {
        fb_plot_raw(fb, x0, y0, color);
        if (x0 == x1 && y0 == y1) {
            break;
        }
        int32_t e2 = 2 * err;
        if (e2 > -dy) { err -= dy; x0 += sx; }
        if (e2 < dx)  { err += dx; y0 += sy; }
    }
}

void fb_rect(struct fb *fb, int32_t x, int32_t y, int32_t w, int32_t h, uint16_t color) {
    if (w <= 0 || h <= 0) return;
    fb_hline(fb, x, y, w, color);
    fb_hline(fb, x, y + h - 1, w, color);
    fb_vline(fb, x, y, h, color);
    fb_vline(fb, x + w - 1, y, h, color);
}

void fb_fill_rect(struct fb *fb, int32_t x, int32_t y, int32_t w, int32_t h, uint16_t color) {
    if (!fb || !fb->pixels || w <= 0 || h <= 0) return;
    int32_t x0 = x < 0 ? 0 : x;
    int32_t y0 = y < 0 ? 0 : y;
    int32_t x1 = x + w - 1;
    int32_t y1 = y + h - 1;
    if (x1 >= fb->width) x1 = fb->width - 1;
    if (y1 >= fb->height) y1 = fb->height - 1;
    if (x0 > x1 || y0 > y1) return;

    for (int32_t cy = y0; cy <= y1; cy++) {
        uint16_t *row = &fb->pixels[(uint32_t)cy * fb->width];
        for (int32_t cx = x0; cx <= x1; cx++) {
            row[cx] = color;
        }
    }
    fb_mark_dirty(fb, x0, y0, x1, y1);
}

void fb_circle(struct fb *fb, int32_t cx, int32_t cy, int32_t r, uint16_t color) {
    if (!fb || !fb->pixels || r < 0) return;
    fb_mark_dirty(fb, cx - r, cy - r, cx + r, cy + r);
    int32_t x = r;
    int32_t y = 0;
    int32_t err = 1 - r;
    while (x >= y) {
        fb_plot_raw(fb, cx + x, cy + y, color);
        fb_plot_raw(fb, cx + y, cy + x, color);
        fb_plot_raw(fb, cx - y, cy + x, color);
        fb_plot_raw(fb, cx - x, cy + y, color);
        fb_plot_raw(fb, cx - x, cy - y, color);
        fb_plot_raw(fb, cx - y, cy - x, color);
        fb_plot_raw(fb, cx + y, cy - x, color);
        fb_plot_raw(fb, cx + x, cy - y, color);
        y++;
        if (err < 0) {
            err += 2 * y + 1;
        } else {
            x--;
            err += 2 * (y - x) + 1;
        }
    }
}

void fb_fill_circle(struct fb *fb, int32_t cx, int32_t cy, int32_t r, uint16_t color) {
    if (!fb || !fb->pixels || r < 0) return;
    int32_t x = r;
    int32_t y = 0;
    int32_t err = 1 - r;
    while (x >= y) {
        fb_hline(fb, cx - x, cy + y, 2 * x + 1, color);
        fb_hline(fb, cx - x, cy - y, 2 * x + 1, color);
        fb_hline(fb, cx - y, cy + x, 2 * y + 1, color);
        fb_hline(fb, cx - y, cy - x, 2 * y + 1, color);
        y++;
        if (err < 0) {
            err += 2 * y + 1;
        } else {
            x--;
            err += 2 * (y - x) + 1;
        }
    }
}

void fb_fill_round_rect(struct fb *fb, int32_t x, int32_t y, int32_t w, int32_t h,
                        int32_t r, uint16_t color) {
    if (w <= 0 || h <= 0) return;
    if (r <= 0) {
        fb_fill_rect(fb, x, y, w, h, color);
        return;
    }
    if (2 * r > w) r = w / 2;
    if (2 * r > h) r = h / 2;
    fb_fill_rect(fb, x + r, y, w - 2 * r, h, color);
    fb_fill_rect(fb, x, y + r, r, h - 2 * r, color);
    fb_fill_rect(fb, x + w - r, y + r, r, h - 2 * r, color);
    fb_fill_circle(fb, x + r, y + r, r, color);
    fb_fill_circle(fb, x + w - r - 1, y + r, r, color);
    fb_fill_circle(fb, x + r, y + h - r - 1, r, color);
    fb_fill_circle(fb, x + w - r - 1, y + h - r - 1, r, color);
}

void fb_fill_triangle(struct fb *fb, int32_t x0, int32_t y0,
                      int32_t x1, int32_t y1, int32_t x2, int32_t y2, uint16_t color) {
    if (!fb || !fb->pixels) return;
    if (y0 > y1) { int32_t t = y0; y0 = y1; y1 = t; t = x0; x0 = x1; x1 = t; }
    if (y1 > y2) { int32_t t = y1; y1 = y2; y2 = t; t = x1; x1 = x2; x2 = t; }
    if (y0 > y1) { int32_t t = y0; y0 = y1; y1 = t; t = x0; x0 = x1; x1 = t; }

    int32_t total_h = y2 - y0;
    if (total_h == 0) {
        int32_t minx = x0 < x1 ? x0 : x1;
        if (x2 < minx) minx = x2;
        int32_t maxx = x0 > x1 ? x0 : x1;
        if (x2 > maxx) maxx = x2;
        fb_hline(fb, minx, y0, maxx - minx + 1, color);
        return;
    }

    for (int32_t y = y0; y <= y2; y++) {
        bool second = (y > y1) || (y1 == y0);
        int32_t seg_h = second ? (y2 - y1) : (y1 - y0);
        if (seg_h == 0) seg_h = 1;
        int32_t xa = x0 + ((x2 - x0) * (y - y0)) / total_h;
        int32_t xb = second
            ? (x1 + ((x2 - x1) * (y - y1)) / seg_h)
            : (x0 + ((x1 - x0) * (y - y0)) / seg_h);
        if (xa > xb) { int32_t t = xa; xa = xb; xb = t; }
        fb_hline(fb, xa, y, xb - xa + 1, color);
    }
}

void fb_draw_char(struct fb *fb, int32_t x, int32_t y, char c,
                  uint16_t fg, uint16_t bg, bool draw_bg, uint8_t scale) {
    if (!fb || !fb->pixels || scale == 0) return;
    unsigned char uc = (unsigned char)c;
    if (uc < 0x20u || uc > 0x7Eu) {
        uc = '?';
    }
    const uint8_t *glyph = fb_font5x7[uc - 0x20u];
    for (uint8_t col = 0; col < FB_FONT_W; col++) {
        uint8_t bits = glyph[col];
        for (uint8_t row = 0; row < FB_FONT_H; row++) {
            bool on = (bits & (1u << row)) != 0;
            if (on || draw_bg) {
                fb_fill_rect(fb, x + (int32_t)col * scale, y + (int32_t)row * scale,
                             scale, scale, on ? fg : bg);
            }
        }
    }
    if (draw_bg) {
        fb_fill_rect(fb, x + (int32_t)FB_FONT_W * scale, y,
                     scale, (int32_t)FB_FONT_H * scale, bg);
    }
}

void fb_draw_text(struct fb *fb, int32_t x, int32_t y, const char *text,
                  uint16_t fg, uint16_t bg, bool draw_bg, uint8_t scale) {
    if (!fb || !text || scale == 0) return;
    int32_t cx = x;
    int32_t cy = y;
    for (const char *p = text; *p; p++) {
        if (*p == '\n') {
            cx = x;
            cy += (int32_t)(FB_FONT_H + 2u) * scale;
            continue;
        }
        fb_draw_char(fb, cx, cy, *p, fg, bg, draw_bg, scale);
        cx += (int32_t)FB_FONT_ADV * scale;
    }
}

uint32_t fb_text_width(const char *text, uint8_t scale) {
    if (!text || scale == 0) return 0;
    uint32_t max_chars = 0;
    uint32_t cur = 0;
    for (const char *p = text; *p; p++) {
        if (*p == '\n') {
            if (cur > max_chars) max_chars = cur;
            cur = 0;
        } else {
            cur++;
        }
    }
    if (cur > max_chars) max_chars = cur;
    if (max_chars == 0) return 0;
    return (max_chars * FB_FONT_ADV - 1u) * scale;
}
