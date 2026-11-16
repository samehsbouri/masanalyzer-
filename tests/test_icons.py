"""Launcher icons: the PNG codec, adaptive layer compositing, extraction."""

import zipfile

from masanalyzer.android import icons, raster

ADAPTIVE_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b'<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
    b'  <background android:drawable="%s"/>\n'
    b'  <foreground android:drawable="%s"/>\n'
    b'</adaptive-icon>\n'
)
ADAPTIVE_NAME = "res/mipmap-anydpi-v26/ic_launcher.xml"


def _png(width, height, fill=(0, 0, 0, 0), box=None):
    """Encode a flat RGBA image, optionally with a solid rectangle."""
    image = raster.Raster(width, height)
    image.pixels[:] = bytes(fill) * (width * height)
    if box:
        x0, y0, x1, y1, colour = box
        for y in range(y0, y1):
            for x in range(x0, x1):
                offset = (y * width + x) * 4
                image.pixels[offset:offset + 4] = bytes(colour)
    return raster.encode_png(image)


def _apk(tmp_path, files, name="app.apk"):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        for entry, blob in files.items():
            archive.writestr(entry, blob)
    return str(path)


# --------------------------------------------------------------------------
# PNG codec
# --------------------------------------------------------------------------
def test_png_roundtrip_preserves_rgba():
    image = raster.Raster(4, 3)
    for i in range(0, len(image.pixels), 4):
        image.pixels[i] = i * 3 % 256
        image.pixels[i + 1] = (i * 7) % 256
        image.pixels[i + 2] = (i * 11) % 256
        image.pixels[i + 3] = 255 if i % 8 else 128
    decoded = raster.decode_png(raster.encode_png(image))
    assert decoded is not None
    assert (decoded.width, decoded.height) == (4, 3)
    assert bytes(decoded.pixels) == bytes(image.pixels)


def test_decode_rejects_non_png():
    assert raster.decode_png(b"RIFF....WEBPVP8 ") is None
    assert raster.decode_png(b"") is None


def test_resize_keeps_transparent_edges_clean():
    image = raster.solid(8, (255, 0, 0, 255))
    scaled = raster.resize(image, 32, 32)
    assert scaled.pixel(0, 0)[3] == 255
    assert scaled.pixel(31, 31)[:3] == (255, 0, 0)


# --------------------------------------------------------------------------
# adaptive icons
# --------------------------------------------------------------------------
def test_adaptive_layers_are_composited_into_one_png(tmp_path):
    foreground = _png(108, 108, box=(42, 42, 66, 66, (255, 0, 0, 255)))
    path = _apk(tmp_path, {
        ADAPTIVE_NAME: ADAPTIVE_XML % (b"@0x7f0a0001",
                                       b"@mipmap/ic_launcher_foreground"),
        "res/mipmap-xxhdpi/ic_launcher_foreground.png": foreground,
    })
    colours = {0x7F0A0001: 0xFF1E88E5}  # opaque blue background
    with zipfile.ZipFile(path) as archive:
        hit = icons._from_adaptive(archive, ADAPTIVE_NAME, {}, colours)

    assert hit is not None
    name, blob = hit
    assert name.endswith(".png")
    icon = raster.decode_png(blob)
    assert icon is not None
    assert (icon.width, icon.height) == (icons.ADAPTIVE_SIZE, icons.ADAPTIVE_SIZE)

    centre = icon.pixel(icons.ADAPTIVE_SIZE // 2, icons.ADAPTIVE_SIZE // 2)
    corner = icon.pixel(1, 1)
    assert centre[0] > 200 and centre[1] < 60 and centre[3] == 255
    assert corner[:3] == (30, 136, 229) and corner[3] == 255


def test_adaptive_uses_layer_images_for_both_layers(tmp_path):
    background = _png(108, 108, fill=(20, 120, 60, 255))
    foreground = _png(108, 108)
    path = _apk(tmp_path, {
        ADAPTIVE_NAME: ADAPTIVE_XML % (b"@mipmap/ic_launcher_background",
                                       b"@mipmap/ic_launcher_foreground"),
        "res/mipmap-hdpi/ic_launcher_background.png": background,
        "res/mipmap-hdpi/ic_launcher_foreground.png": foreground,
    })
    with zipfile.ZipFile(path) as archive:
        hit = icons._from_adaptive(archive, ADAPTIVE_NAME, {}, {})

    assert hit is not None
    icon = raster.decode_png(hit[1])
    assert icon.pixel(0, 0)[:3] == (20, 120, 60)


def test_webp_layers_fall_back_to_one_svg(tmp_path):
    webp = b"RIFF\x10\x00\x00\x00WEBPVP8 " + b"\x00" * 8
    path = _apk(tmp_path, {
        ADAPTIVE_NAME: ADAPTIVE_XML % (b"@mipmap/bg", b"@mipmap/fg"),
        "res/mipmap-hdpi/bg.webp": webp,
        "res/mipmap-hdpi/fg.webp": webp,
    })
    with zipfile.ZipFile(path) as archive:
        hit = icons._from_adaptive(archive, ADAPTIVE_NAME, {}, {})

    assert hit is not None
    name, blob = hit
    assert name.endswith(".svg")
    svg = blob.decode("utf-8")
    # cropped to the 72/108 launcher safe zone, one document, no side files
    assert "viewBox='18 18 72 72'" in svg
    assert svg.count("data:image/webp;base64,") == 2
    assert svg.startswith("<svg") and svg.endswith("</svg>")


def test_adaptive_with_only_unresolvable_layers_returns_none(tmp_path):
    path = _apk(tmp_path, {
        ADAPTIVE_NAME: ADAPTIVE_XML % (b"@color/bg", b"@color/fg"),
    })
    with zipfile.ZipFile(path) as archive:
        assert icons._from_adaptive(archive, ADAPTIVE_NAME, {}, {}) is None


def test_adaptive_sibling_prefers_the_anydpi_xml():
    names = {
        "res/mipmap-mdpi-v4/ic_launcher.webp",
        "res/mipmap-anydpi-v26/ic_launcher.xml",
        "res/mipmap-anydpi-v26/ic_launcher_round.xml",
    }
    assert icons._adaptive_sibling(
        names, "res/mipmap-mdpi-v4/ic_launcher.webp"
    ) == "res/mipmap-anydpi-v26/ic_launcher.xml"
    assert icons._adaptive_sibling(
        names, "res/mipmap-mdpi-v4/other.webp") == ""


def test_adaptive_ignores_malformed_document(tmp_path):
    path = _apk(tmp_path, {ADAPTIVE_NAME: b"not xml at all"})
    with zipfile.ZipFile(path) as archive:
        assert icons._from_adaptive(archive, ADAPTIVE_NAME, {}, {}) is None


def test_entry_for_prefers_the_densest_layer():
    names = {
        "res/mipmap-mdpi/ic.png",
        "res/mipmap-xxxhdpi/ic.png",
        "res/mipmap-hdpi/ic.webp",
        "res/drawable/other.png",
    }
    assert icons._entry_for(names, "ic") == "res/mipmap-xxxhdpi/ic.png"


def test_parse_colour_forms():
    assert icons._parse_color("#1e88e5") == (30, 136, 229, 255)
    assert icons._parse_color("#801e88e5") == (30, 136, 229, 128)
    assert icons._parse_color("#abc") == (170, 187, 204, 255)
    assert icons._parse_color("#12345") is None
    assert icons._parse_color("#zzzzzz") is None


# --------------------------------------------------------------------------
# extract_icon
# --------------------------------------------------------------------------
def test_extract_icon_falls_back_to_largest_square(tmp_path):
    small = _png(48, 48, fill=(1, 2, 3, 255))
    big = _png(96, 96, fill=(9, 8, 7, 255))
    path = _apk(tmp_path, {
        "res/drawable/small.png": small,
        "res/drawable/big.png": big,
        "res/drawable/nine.png": b"npTc" + b"\x00" * 64,
        "res/drawable/wide.png": _png(120, 60),
    })
    hit = icons.extract_icon(path)
    assert hit is not None
    assert hit[1] == "png"
    assert hit[0] == big


def test_extract_icon_on_non_zip(tmp_path):
    path = tmp_path / "broken.apk"
    path.write_bytes(b"not a zip")
    assert icons.extract_icon(str(path)) is None
