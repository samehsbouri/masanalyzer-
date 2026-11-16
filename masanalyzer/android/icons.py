"""Launcher icon extraction for uploaded bundles.

The dashboard shows a bundle's own app icon next to its name.  For an APK the
icon is a resource reference, so this resolves it the way the platform does:

1. read ``android:icon`` (and ``android:roundIcon``) from the compiled
   manifest, which arrives as ``@res/0x7f110000`` or a bare resource id;
2. resolve that id through ``resources.arsc`` to the file name inside the
   archive (``res/jB.webp`` in an obfuscated build);
3. when that name is an adaptive icon (``mipmap-anydpi-v26/ic_launcher.xml``),
   read its ``<background>`` / ``<foreground>`` layers and composite them into
   one PNG the way a launcher draws them;
4. fall back to the largest square PNG/WebP under ``res/`` for tables the
   reader cannot resolve.

Everything is best-effort: a missing or unreadable icon returns ``None`` so a
scan never fails over decoration.  No third-party code - the only decoding is
the PNG codec in :mod:`masanalyzer.android.raster`, used for adaptive layers.
"""

from __future__ import annotations

import base64
import re
import struct
import zipfile
from typing import List, Optional, Tuple

from .axml import AXmlError, parse_xml_any
from .raster import Color, Raster, compose_adaptive, decode_png, encode_png
from .resources import resource_colors, resource_strings

#: largest icon we will hand to the browser
MAX_ICON_BYTES = 512 * 1024
#: extensions browsers render directly
_IMAGE_EXT = (".png", ".webp", ".jpg", ".jpeg")
#: resource-ish references: ``@drawable/name``, ``@mipmap/name``, ``@color/name``
_REF = re.compile(r"^@(?:\+)?([A-Za-z0-9_.]+)/([A-Za-z0-9_.]+)$")
#: adaptive icon output size and the launcher's safe zone (72 of 108dp)
ADAPTIVE_SIZE = 192
#: density buckets, best first (used to break ties when a layer repeats)
_DENSITY = ("xxxhdpi", "xxhdpi", "xhdpi", "hdpi", "mdpi", "ldpi")
_RES_ID = re.compile(r"0x([0-9a-fA-F]{8})")


def extract_icon(path: str) -> Optional[Tuple[bytes, str]]:
    """Return ``(image_bytes, extension)`` for the bundle's app icon.

    ``extension`` is ``png``/``webp``/``jpg`` without the dot.  Returns
    ``None`` when the bundle carries no usable icon (or is not a zip).
    """
    try:
        with zipfile.ZipFile(path) as archive:
            hit = _from_manifest(archive) or _largest_square(archive)
    except (OSError, zipfile.BadZipFile):
        return None
    if not hit:
        return None
    name, data = hit
    if not data or len(data) > MAX_ICON_BYTES:
        return None
    ext = name.rsplit(".", 1)[-1].lower()
    return data, ("jpg" if ext == "jpeg" else ext)


# --------------------------------------------------------------------------
# manifest -> resource id -> archive entry
# --------------------------------------------------------------------------
def _from_manifest(archive: zipfile.ZipFile) -> Optional[Tuple[str, bytes]]:
    ids = _icon_resource_ids(archive)
    if not ids:
        return None
    try:
        arsc = archive.read("resources.arsc")
        mapping = resource_strings(arsc)
        colors = resource_colors(arsc)
    except (KeyError, OSError):
        mapping, colors = {}, {}
    names = set(archive.namelist())
    for rid in ids:
        name = mapping.get(rid)
        if not name:
            continue
        # the table resolves to the first matching config (usually mdpi
        # webp); the adaptive icon for the same resource lives in anydpi-v26
        adaptive = _adaptive_sibling(names, name)
        if adaptive:
            hit = _from_adaptive(archive, adaptive, mapping, colors)
            if hit:
                return hit
        lower = name.lower()
        if lower.endswith(_IMAGE_EXT) and name in names:
            try:
                return name, archive.read(name)
            except OSError:
                continue
        if lower.endswith(".xml"):
            hit = _from_adaptive(archive, name, mapping, colors)
            if hit:
                return hit
    return None


def _adaptive_sibling(names: set, name: str) -> str:
    """The ``anydpi`` adaptive-icon XML sharing a bitmap's resource name."""
    leaf = name.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
    if not leaf:
        return ""
    fallback = ""
    for entry in names:
        low = entry.lower()
        if not low.startswith("res/") or not low.endswith(".xml"):
            continue
        if "anydpi" not in low:
            continue
        if low.rsplit("/", 1)[-1].rsplit(".", 1)[0] != leaf:
            continue
        if "mipmap-anydpi-v26" in low:
            return entry
        fallback = fallback or entry
    return fallback


def _icon_resource_ids(archive: zipfile.ZipFile) -> List[int]:
    """Resource ids named by ``android:icon`` / ``android:roundIcon``."""
    try:
        tree = parse_xml_any(archive.read("AndroidManifest.xml"))
    except (KeyError, OSError, ValueError):
        return []
    app = _find(tree, "application")
    if app is None:
        return []
    out: List[int] = []
    for attr in ("icon", "roundIcon"):
        raw = app.get(attr)
        rid = _as_resource_id(raw)
        if rid is not None and rid not in out:
            out.append(rid)
    return out


def _as_resource_id(value: object) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if value > 0x01000000 else None
    text = str(value)
    match = _RES_ID.search(text)
    if match:
        return int(match.group(1), 16)
    if text.isdigit():
        number = int(text)
        return number if number > 0x01000000 else None
    return None


def _find(node: object, tag: str) -> Optional[object]:
    for child in getattr(node, "children", []) or []:
        if getattr(child, "tag", "") == tag:
            return child
        found = _find(child, tag)
        if found is not None:
            return found
    return None


# --------------------------------------------------------------------------
# adaptive icons: mipmap-anydpi-v26/ic_launcher.xml -> layered PNG
# --------------------------------------------------------------------------
def _from_adaptive(
    archive: zipfile.ZipFile,
    name: str,
    mapping: Optional[dict] = None,
    colors: Optional[dict] = None,
) -> Optional[Tuple[str, bytes]]:
    """Composite ``<adaptive-icon>`` layers into a single PNG.

    ``mapping`` / ``colors`` are the ``resources.arsc`` lookups already loaded
    by :func:`_from_manifest`; they may be omitted (tests, odd archives).
    """
    try:
        tree = parse_xml_any(archive.read(name))
    except (KeyError, OSError, ValueError, AXmlError):
        return None
    node = _find_adaptive(tree)
    if node is None:
        return None
    names = set(archive.namelist())
    background = _layer(archive, _drawable(node, "background"),
                        mapping or {}, colors or {}, names)
    foreground = _layer(archive, _drawable(node, "foreground"),
                        mapping or {}, colors or {}, names)
    if background is None and foreground is None:
        return None
    icon = _raster_composite(background, foreground)
    if icon is not None:
        return "res/adaptive-icon.png", encode_png(icon)
    # layers we cannot decode (WebP, JPEG) still composite - as an SVG that
    # references them, which every browser draws natively
    svg = _svg_composite(background, foreground)
    if svg is not None:
        return "res/adaptive-icon.svg", svg
    return None


def _raster_composite(background, foreground) -> Optional[Raster]:
    """PNG/colour layers -> one raster; ``None`` if a layer is undecodable."""
    layers = []
    for layer in (background, foreground):
        if layer is None:
            layers.append(None)
            continue
        if layer[0] == "color":
            layers.append(layer[1])
            continue
        decoded = decode_png(layer[2])
        if decoded is None:
            return None
        layers.append(decoded)
    return compose_adaptive(layers[0], layers[1], ADAPTIVE_SIZE)


_SVG_MIME = {
    "png": "image/png",
    "webp": "image/webp",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
}
#: refuse to inline more than this much layer data in one SVG
_MAX_SVG_LAYER_BYTES = 1024 * 1024


def _svg_composite(background, foreground) -> Optional[bytes]:
    """Build an SVG that draws the layers, cropped to the launcher mask."""
    body = []
    for layer in (background, foreground):
        if layer is None:
            continue
        if layer[0] == "color":
            r, g, b, a = layer[1]
            body.append(
                f"<rect x='0' y='0' width='108' height='108' "
                f"fill='#{r:02x}{g:02x}{b:02x}' "
                f"fill-opacity='{a / 255:.3f}'/>")
            continue
        mime = _SVG_MIME.get(layer[1])
        data = layer[2]
        if not mime or not data or len(data) > _MAX_SVG_LAYER_BYTES:
            return None
        payload = base64.b64encode(data).decode("ascii")
        body.append(
            "<image x='0' y='0' width='108' height='108' "
            "preserveAspectRatio='xMidYMid meet' "
            f"href='data:{mime};base64,{payload}'/>")
    if not body:
        return None
    return (
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='18 18 72 72' "
        f"width='{ADAPTIVE_SIZE}' height='{ADAPTIVE_SIZE}'>"
        + "".join(body) + "</svg>"
    ).encode("utf-8")


def _find_adaptive(node: object) -> Optional[object]:
    if getattr(node, "tag", "") == "adaptive-icon":
        return node
    return _find(node, "adaptive-icon")


def _drawable(node: object, tag: str) -> Optional[str]:
    """The ``android:drawable`` reference of a layer child, if present."""
    for child in getattr(node, "children", []) or []:
        if getattr(child, "tag", "") != tag:
            continue
        for key in ("drawable", "android:drawable"):
            try:
                value = child.get(key)
            except (AttributeError, KeyError):
                continue
            if value:
                return str(value)
    return None


#: a resolved layer: ``("color", (r,g,b,a))`` or ``("image", ext, bytes)``
Layer = Tuple[str, object]


def _layer(archive: zipfile.ZipFile, value: Optional[str], mapping: dict,
           colors: dict, names: set) -> Optional[Layer]:
    """Resolve one layer reference to a colour or an image blob."""
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("#"):
        color = _parse_color(text)
        return ("color", color) if color else None

    rid = _as_resource_id(text)
    if rid is not None:
        if rid in colors:
            return ("color", _argb(int(colors[rid])))
        resolved = mapping.get(rid)
        return _image_layer(archive, resolved, names) if resolved else None

    match = _REF.match(text)
    if match:
        kind, base = match.group(1), match.group(2)
        if kind == "color":
            # a colour name carries no archive entry; the compiled form is a
            # resource id handled above
            return None
        entry = _entry_for(names, base)
        return _image_layer(archive, entry, names) if entry else None
    return _image_layer(archive, text, names)


def _image_layer(archive: zipfile.ZipFile, name: str,
                 names: set) -> Optional[Layer]:
    """Read one layer image; keeps the bytes so SVG can reference them."""
    if not name:
        return None
    if name not in names:
        name = _entry_for(names, name.rsplit("/", 1)[-1])
        if not name:
            return None
    else:
        # the table points at one config (usually mdpi); take the densest
        # variant of the same layer so the icon is not upscaled
        densest = _entry_for(names, name.rsplit("/", 1)[-1])
        if densest:
            name = densest
    ext = name.rsplit(".", 1)[-1].lower()
    if ext not in ("png", "webp", "jpg", "jpeg"):
        return None
    try:
        data = archive.read(name)
    except (OSError, zipfile.BadZipFile):
        return None
    if not data or len(data) > MAX_ICON_BYTES:
        return None
    return ("image", "jpg" if ext == "jpeg" else ext, data)


def _entry_for(names: set, base: str) -> str:
    """Best archive entry whose file name is ``base`` (any density)."""
    stem = base.rsplit(".", 1)[0].lower()
    if not stem:
        return ""
    best: Optional[Tuple[int, str]] = None
    for name in names:
        if not name.startswith("res/"):
            continue
        low = name.lower()
        if not low.endswith(_IMAGE_EXT):
            continue
        if low.rsplit("/", 1)[-1].rsplit(".", 1)[0] != stem:
            continue
        rank = len(_DENSITY)
        for index, bucket in enumerate(_DENSITY):
            if bucket in low:
                rank = index
                break
        key = (rank, name)
        if best is None or key < best:
            best = key
    return best[1] if best else ""


def _argb(value: int) -> Color:
    value &= 0xFFFFFFFF
    return ((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF,
            (value >> 24) & 0xFF)


def _parse_color(text: str) -> Optional[Color]:
    digits = text.lstrip("#")
    if len(digits) == 3:
        digits = "".join(ch * 2 for ch in digits)
    if len(digits) == 4:
        digits = "".join(ch * 2 for ch in digits)
    if len(digits) == 6:
        digits = "ff" + digits
    if len(digits) != 8:
        return None
    try:
        return _argb(int(digits, 16))
    except ValueError:
        return None


# --------------------------------------------------------------------------
# fallback: biggest square image under res/
# --------------------------------------------------------------------------
def _largest_square(archive: zipfile.ZipFile) -> Optional[Tuple[str, bytes]]:
    best: Optional[Tuple[int, str, bytes]] = None
    for info in archive.infolist():
        name = info.filename
        if not name.startswith("res/") or not name.lower().endswith(_IMAGE_EXT):
            continue
        if info.file_size <= 0 or info.file_size > MAX_ICON_BYTES:
            continue
        try:
            data = archive.read(name)
        except (OSError, zipfile.BadZipFile):
            continue
        if b"npTc" in data[:2048]:
            continue  # nine-patch, not a launcher icon
        size = _image_size(data)
        if size is None:
            continue
        width, height = size
        if width < 48 or height < 48:
            continue
        if not 0.9 <= width / height <= 1.12:
            continue
        if best is None or width * height > best[0]:
            best = (width * height, name, data)
    return (best[1], best[2]) if best else None


def _image_size(data: bytes) -> Optional[Tuple[int, int]]:
    """Width/height from a PNG or WebP header (enough to pick a square)."""
    if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n":
        try:
            width, height = struct.unpack(">II", data[16:24])
        except struct.error:
            return None
        return (width, height) if width and height else None
    if len(data) >= 30 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        kind = data[12:16]
        try:
            if kind == b"VP8L":
                b0, b1, b2, b3 = data[21:25]
                width = 1 + (b0 | ((b1 & 0x3F) << 8))
                height = 1 + ((b1 >> 6) | (b2 << 2) | ((b3 & 0x0F) << 10))
                return width, height
            if kind == b"VP8 ":
                width, height = struct.unpack("<HH", data[26:30])
                return width & 0x3FFF, height & 0x3FFF
            if kind == b"VP8X":
                width = 1 + int.from_bytes(data[24:27], "little")
                height = 1 + int.from_bytes(data[27:30], "little")
                return width, height
        except struct.error:
            return None
    return None
