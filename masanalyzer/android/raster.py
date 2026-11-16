"""Just enough raster code to composite an adaptive icon.

Android ships adaptive launcher icons as two layers (background + foreground)
that the launcher draws on top of each other inside a mask.  The dashboard has
no Pillow and never decodes arbitrary images, so this module carries the small
amount of raster work the icon path needs:

* ``decode_png`` - PNG with 8/16-bit samples, grayscale/truecolour/palette,
  non-interlaced (the formats adaptive layers actually use);
* ``encode_png`` - 8-bit RGBA output;
* ``resize`` / ``over`` / ``compose_adaptive`` - bilinear scaling with
  premultiplied alpha and straight source-over compositing.

Anything it cannot read (interlaced PNG, WebP) yields ``None`` so the caller
falls back instead of failing a scan.
"""

from __future__ import annotations

import struct
import zlib
from typing import List, Optional, Tuple, Union

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
#: layers larger than this are not worth decoding for a 192px icon
MAX_SIDE = 1024
_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}

Color = Tuple[int, int, int, int]


class Raster:
    """An 8-bit RGBA image held as one flat ``bytearray``."""

    __slots__ = ("width", "height", "pixels")

    def __init__(self, width: int, height: int,
                 pixels: Optional[bytearray] = None) -> None:
        self.width = int(width)
        self.height = int(height)
        if pixels is None:
            pixels = bytearray(self.width * self.height * 4)
        self.pixels = pixels

    def pixel(self, x: int, y: int) -> Color:
        offset = (y * self.width + x) * 4
        p = self.pixels
        return (p[offset], p[offset + 1], p[offset + 2], p[offset + 3])


# --------------------------------------------------------------------------
# PNG decoding
# --------------------------------------------------------------------------
def decode_png(data: bytes) -> Optional[Raster]:
    """Decode a PNG into a :class:`Raster`, or ``None`` if unsupported."""
    if len(data) < 8 or data[:8] != PNG_SIGNATURE:
        return None
    pos = 8
    header: Optional[Tuple] = None
    palette = b""
    trns = b""
    idat: List[bytes] = []
    while pos + 8 <= len(data):
        (length,) = struct.unpack_from(">I", data, pos)
        kind = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            if len(body) < 13:
                return None
            header = struct.unpack(">IIBBBBB", body[:13])
        elif kind == b"PLTE":
            palette = body
        elif kind == b"tRNS":
            trns = body
        elif kind == b"IDAT":
            idat.append(body)
        elif kind == b"IEND":
            break
    if header is None or not idat:
        return None
    width, height, depth, color, _comp, _filt, interlace = header
    channels = _CHANNELS.get(color)
    if channels is None or interlace or depth not in (1, 2, 4, 8, 16):
        return None
    if width <= 0 or height <= 0 or width > MAX_SIDE or height > MAX_SIDE:
        return None
    if color == 3 and len(palette) < 3:
        return None
    if depth < 8 and color not in (0, 3):
        return None
    try:
        raw = zlib.decompress(b"".join(idat))
    except zlib.error:
        return None
    bits = channels * depth
    stride = (width * bits + 7) // 8
    bpp = max(1, bits // 8)
    if len(raw) < (stride + 1) * height:
        return None

    raster = Raster(width, height)
    prev = bytearray(stride)
    pos = 0
    for y in range(height):
        ftype = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        _unfilter(ftype, line, prev, bpp)
        prev = line
        _row_to_rgba(line, raster.pixels, y * width * 4, width, depth, color,
                     channels, palette, trns)
    return raster


def _unfilter(ftype: int, line: bytearray, prev: bytearray, bpp: int) -> None:
    """Reverse one PNG scanline filter in place."""
    n = len(line)
    if ftype == 0 or n == 0:
        return
    if ftype == 1:  # Sub
        for i in range(bpp, n):
            line[i] = (line[i] + line[i - bpp]) & 0xFF
    elif ftype == 2:  # Up
        for i in range(n):
            line[i] = (line[i] + prev[i]) & 0xFF
    elif ftype == 3:  # Average
        for i in range(n):
            left = line[i - bpp] if i >= bpp else 0
            line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
    elif ftype == 4:  # Paeth
        for i in range(n):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            p = a + b - c
            pa = abs(p - a)
            pb = abs(p - b)
            pc = abs(p - c)
            if pa <= pb and pa <= pc:
                pred = a
            elif pb <= pc:
                pred = b
            else:
                pred = c
            line[i] = (line[i] + pred) & 0xFF


def _samples(line: bytearray, count: int, depth: int):
    """Per-sample values from one unfiltered scanline."""
    if depth == 8:
        return line
    if depth == 16:
        return [line[2 * i] for i in range(count)]
    per_byte = 8 // depth
    mask = (1 << depth) - 1
    out = []
    for i in range(count):
        byte = line[i // per_byte]
        shift = 8 - depth * (i % per_byte + 1)
        out.append((byte >> shift) & mask)
    return out


def _row_to_rgba(line, out, offset, width, depth, color, channels,
                 palette, trns) -> None:
    samples = _samples(line, width * channels, depth)
    scale = 255 // ((1 << depth) - 1) if depth < 8 else 1
    for x in range(width):
        i = x * channels
        if color == 3:  # palette
            index = samples[i]
            base = index * 3
            if base + 2 >= len(palette):
                r = g = b = 0
            else:
                r, g, b = palette[base], palette[base + 1], palette[base + 2]
            a = trns[index] if index < len(trns) else 255
        elif color == 0:  # grayscale
            r = g = b = samples[i] * scale
            a = 255
        elif color == 4:  # grayscale + alpha
            r = g = b = samples[i] * scale
            a = samples[i + 1] * scale
        elif color == 2:  # truecolour
            r, g, b = samples[i], samples[i + 1], samples[i + 2]
            a = 255
        else:  # colour 6: truecolour + alpha
            r, g, b, a = (samples[i], samples[i + 1], samples[i + 2],
                          samples[i + 3])
        o = offset + x * 4
        out[o] = r
        out[o + 1] = g
        out[o + 2] = b
        out[o + 3] = a


# --------------------------------------------------------------------------
# PNG encoding
# --------------------------------------------------------------------------
def encode_png(raster: Raster) -> bytes:
    """Encode a raster as an 8-bit RGBA PNG."""
    width, height = raster.width, raster.height
    stride = width * 4
    raw = bytearray((stride + 1) * height)
    src = raster.pixels
    for y in range(height):
        offset = y * (stride + 1)
        raw[offset] = 0  # filter: none
        raw[offset + 1:offset + 1 + stride] = src[y * stride:(y + 1) * stride]
    return (
        PNG_SIGNATURE
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + _chunk(b"IEND", b"")
    )


def _chunk(kind: bytes, body: bytes) -> bytes:
    return (struct.pack(">I", len(body)) + kind + body
            + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF))


# --------------------------------------------------------------------------
# compositing
# --------------------------------------------------------------------------
def solid(size: int, color: Color) -> Raster:
    """A ``size`` square filled with ``color``."""
    raster = Raster(size, size)
    raster.pixels[:] = bytes(color) * (size * size)
    return raster


def resize(raster: Raster, width: int, height: int) -> Raster:
    """Bilinear resize (premultiplied, so transparent edges stay clean)."""
    width = max(1, int(width))
    height = max(1, int(height))
    if raster.width == width and raster.height == height:
        return raster
    src = raster.pixels
    sw, sh = raster.width, raster.height
    out = Raster(width, height)
    dst = out.pixels
    for y in range(height):
        fy = max(0.0, (y + 0.5) * sh / height - 0.5)
        y0 = min(int(fy), sh - 1)
        y1 = min(y0 + 1, sh - 1)
        wy = fy - y0
        for x in range(width):
            fx = max(0.0, (x + 0.5) * sw / width - 0.5)
            x0 = min(int(fx), sw - 1)
            x1 = min(x0 + 1, sw - 1)
            wx = fx - x0
            o = (y * width + x) * 4
            # sample the four taps premultiplied
            acc = [0.0, 0.0, 0.0, 0.0]
            for (sx, sy, weight) in (
                (x0, y0, (1 - wx) * (1 - wy)),
                (x1, y0, wx * (1 - wy)),
                (x0, y1, (1 - wx) * wy),
                (x1, y1, wx * wy),
            ):
                if weight <= 0.0:
                    continue
                i = (sy * sw + sx) * 4
                alpha = src[i + 3]
                if alpha == 0:
                    continue
                factor = weight * alpha / 255.0
                acc[0] += src[i] * factor
                acc[1] += src[i + 1] * factor
                acc[2] += src[i + 2] * factor
                acc[3] += alpha * weight
            alpha = acc[3]
            dst[o + 3] = int(alpha + 0.5)
            if alpha > 0:
                dst[o] = min(255, int(acc[0] / alpha * 255.0 + 0.5))
                dst[o + 1] = min(255, int(acc[1] / alpha * 255.0 + 0.5))
                dst[o + 2] = min(255, int(acc[2] / alpha * 255.0 + 0.5))
    return out


def over(base: Raster, top: Raster) -> Raster:
    """Source-over ``top`` on ``base`` (both must share a size)."""
    if (base.width, base.height) != (top.width, top.height):
        top = resize(top, base.width, base.height)
    out = Raster(base.width, base.height)
    b, t, o = base.pixels, top.pixels, out.pixels
    for i in range(0, len(o), 4):
        sa = t[i + 3]
        if sa == 0:
            o[i:i + 4] = b[i:i + 4]
            continue
        if sa == 255:
            o[i:i + 4] = t[i:i + 4]
            continue
        sa_f = sa / 255.0
        ba_f = b[i + 3] / 255.0
        keep = ba_f * (1.0 - sa_f)
        out_a = sa_f + keep
        if out_a <= 0.0:
            continue
        for c in range(3):
            o[i + c] = min(255, int((t[i + c] * sa_f + b[i + c] * keep)
                                   / out_a + 0.5))
        o[i + 3] = min(255, int(out_a * 255.0 + 0.5))
    return out


def crop(raster: Raster, x0: int, y0: int, width: int, height: int) -> Raster:
    """Copy a rectangle out of ``raster``."""
    width = max(1, min(width, raster.width))
    height = max(1, min(height, raster.height))
    out = Raster(width, height)
    stride = width * 4
    for y in range(height):
        src = ((y0 + y) * raster.width + x0) * 4
        out.pixels[y * stride:(y + 1) * stride] = raster.pixels[src:src + stride]
    return out


Layer = Union[Raster, Color, None]


def compose_adaptive(background: Layer, foreground: Layer, size: int = 192,
                     safe_zone: float = 72 / 108) -> Optional[Raster]:
    """Stack an adaptive icon's layers and crop it to the launcher mask.

    Android draws both layers on a 108dp canvas and masks the central 72dp,
    so the composite is cropped to that safe zone before being scaled down.
    """
    rasters = [layer for layer in (background, foreground)
               if isinstance(layer, Raster)]
    if not rasters:
        return None
    side = max(max(r.width, r.height) for r in rasters)
    if side < 8:
        return None

    if isinstance(background, Raster):
        canvas = _cover(background, side)
    elif isinstance(background, tuple) and len(background) == 4:
        canvas = solid(side, background)  # type: ignore[arg-type]
    else:
        canvas = solid(side, (0, 0, 0, 0))
    if isinstance(foreground, Raster):
        canvas = over(canvas, _fit(foreground, side))

    core = max(1, int(round(side * safe_zone)))
    x0 = (side - core) // 2
    y0 = (side - core) // 2
    return resize(crop(canvas, x0, y0, core, core), size, size)


def _fit(raster: Raster, side: int) -> Raster:
    """Scale to fit inside ``side`` and centre on a transparent canvas."""
    scale = min(side / raster.width, side / raster.height)
    width = max(1, int(round(raster.width * scale)))
    height = max(1, int(round(raster.height * scale)))
    scaled = resize(raster, width, height)
    if width == side and height == side:
        return scaled
    canvas = Raster(side, side)
    x0 = (side - width) // 2
    y0 = (side - height) // 2
    stride = width * 4
    for y in range(height):
        src = y * stride
        dst = ((y0 + y) * side + x0) * 4
        canvas.pixels[dst:dst + stride] = scaled.pixels[src:src + stride]
    return canvas


def _cover(raster: Raster, side: int) -> Raster:
    """Scale to cover ``side`` square and centre-crop the overflow."""
    scale = max(side / raster.width, side / raster.height)
    width = max(1, int(round(raster.width * scale)))
    height = max(1, int(round(raster.height * scale)))
    scaled = resize(raster, width, height)
    x0 = max(0, (width - side) // 2)
    y0 = max(0, (height - side) // 2)
    return crop(scaled, x0, y0, side, side)
