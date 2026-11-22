/* Freestanding RGB565 2D framebuffer, dirty-rect tracking and 5x7 bitmap font. */
#ifndef SPELLBOUND_FB_H
#define SPELLBOUND_FB_H

#include <stdbool.h>
#include <stdint.h>

#define FB_RGB565(r, g, b) \
    ((uint16_t)((((uint16_t)(r) & 0xF8u) << 8) | \
                (((uint16_t)(g) & 0xFCu) << 3) | \
                (((uint16_t)(b) & 0xF8u) >> 3)))

#define FB_BLACK      FB_RGB565(0, 0, 0)
#define FB_WHITE      FB_RGB565(255, 255, 255)
#define FB_GRAY       FB_RGB565(128, 128, 128)
#define FB_DARK_GRAY  FB_RGB565(36, 36, 40)
#define FB_RED        FB_RGB565(235, 64, 52)
#define FB_GREEN      FB_RGB565(46, 204, 113)
#define FB_BLUE       FB_RGB565(52, 152, 219)
#define FB_CYAN       FB_RGB565(0, 210, 211)
#define FB_YELLOW     FB_RGB565(241, 196, 15)
#define FB_ORANGE     FB_RGB565(230, 126, 34)
#define FB_ACCENT     FB_RGB565(138, 108, 255)

#define FB_FONT_W     5u
#define FB_FONT_H     7u
#define FB_FONT_ADV   6u /* 5 px glyph + 1 px spacing */

struct fb_rect {
    uint16_t x0;
    uint16_t y0;
    uint16_t x1; /* inclusive */
    uint16_t y1; /* inclusive */
};

struct fb {
    uint16_t *pixels;
    uint16_t width;
    uint16_t height;
    bool dirty;
    struct fb_rect dirty_rect;
};

int fb_init(struct fb *fb, uint16_t *pixels, uint16_t width, uint16_t height);
void fb_mark_dirty(struct fb *fb, int32_t x0, int32_t y0, int32_t x1, int32_t y1);
void fb_clear_dirty(struct fb *fb);
bool fb_get_dirty(const struct fb *fb, struct fb_rect *out);

void fb_clear(struct fb *fb, uint16_t color);
void fb_put_pixel(struct fb *fb, int32_t x, int32_t y, uint16_t color);
uint16_t fb_get_pixel(const struct fb *fb, int32_t x, int32_t y);

void fb_hline(struct fb *fb, int32_t x, int32_t y, int32_t len, uint16_t color);
void fb_vline(struct fb *fb, int32_t x, int32_t y, int32_t len, uint16_t color);
void fb_line(struct fb *fb, int32_t x0, int32_t y0, int32_t x1, int32_t y1, uint16_t color);
void fb_rect(struct fb *fb, int32_t x, int32_t y, int32_t w, int32_t h, uint16_t color);
void fb_fill_rect(struct fb *fb, int32_t x, int32_t y, int32_t w, int32_t h, uint16_t color);
void fb_fill_round_rect(struct fb *fb, int32_t x, int32_t y, int32_t w, int32_t h,
                        int32_t r, uint16_t color);
void fb_circle(struct fb *fb, int32_t cx, int32_t cy, int32_t r, uint16_t color);
void fb_fill_circle(struct fb *fb, int32_t cx, int32_t cy, int32_t r, uint16_t color);
void fb_fill_triangle(struct fb *fb, int32_t x0, int32_t y0,
                      int32_t x1, int32_t y1, int32_t x2, int32_t y2, uint16_t color);

/* 5x7 ASCII bitmap text rendering with integer scaling (scale >= 1). */
void fb_draw_char(struct fb *fb, int32_t x, int32_t y, char c,
                  uint16_t fg, uint16_t bg, bool draw_bg, uint8_t scale);
void fb_draw_text(struct fb *fb, int32_t x, int32_t y, const char *text,
                  uint16_t fg, uint16_t bg, bool draw_bg, uint8_t scale);
uint32_t fb_text_width(const char *text, uint8_t scale);

#endif /* SPELLBOUND_FB_H */
