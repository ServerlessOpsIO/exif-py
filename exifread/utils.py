"""
Misc utilities.
"""

from fractions import Fraction
import struct
from typing import BinaryIO, Union, Tuple

from .heic import HEICExifFinder
from .exif_log import get_logger

logger = get_logger()

FILE_TYPE_TIFF = 'TIFF'
FILE_TYPE_JPEG = 'JPEG'
FILE_TYPE_HEIC = 'HEIC'
FILE_TYPE_WEBP = 'WEBP'

class InvalidExif(Exception):
    pass


class ExifNotFound(Exception):
    pass


def ord_(dta):
    if isinstance(dta, str):
        return ord(dta)
    return dta


def increment_base(data, base):
    return ord_(data[base + 2]) * 256 + ord_(data[base + 3]) + 2


def find_tiff_exif(fh: BinaryIO) -> Tuple[int, bytes]:
    logger.debug("TIFF format recognized in data[0:2]")
    fh.seek(0)
    endian = fh.read(1)
    fh.read(1)
    offset = 0
    return offset, endian


def find_webp_exif(fh: BinaryIO) -> Tuple[int, bytes]:
    logger.debug("WebP format recognized in data[0:4], data[8:12]")
    # file specification: https://developers.google.com/speed/webp/docs/riff_container
    data = fh.read(5)
    if data[0:4] == b'VP8X' and data[4] & 8:
        # https://developers.google.com/speed/webp/docs/riff_container#extended_file_format
        fh.seek(13, 1)
        while True:
            data = fh.read(8)  # Chunk FourCC (32 bits) and Chunk Size (32 bits)
            if len(data) != 8:
                raise InvalidExif("Invalid webp file chunk header.")
            if data[0:4] == b'EXIF':
                offset = fh.tell()
                endian = fh.read(1)
                return offset, endian
            size = struct.unpack('<L', data[4:8])[0]
            fh.seek(size, 1)
    raise ExifNotFound("Webp file does not have exif data.")


def find_jpeg_exif(fh: BinaryIO, data) -> Tuple[int, bytes]:
    logger.debug("JPEG format recognized data[0:2]=0x%X%X", ord_(data[0]), ord_(data[1]))
    base = 2
    logger.debug("data[2]=0x%X data[3]=0x%X data[6:10]=%s", ord_(data[2]), ord_(data[3]), data[6:10])
    while ord_(data[2]) == 0xFF and data[6:10] in (b'JFIF', b'JFXX', b'OLYM', b'Phot'):
        length = ord_(data[4]) * 256 + ord_(data[5])
        logger.debug(" Length offset is %s", length)
        fh.read(length - 8)
        # fake an EXIF beginning of file
        # I don't think this is used. --gd
        data = b'\xFF\x00' + fh.read(10)
        if base > 2:
            logger.debug(" Added to base")
            base = base + length + 4 - 2
        else:
            logger.debug(" Added to zero")
            base = length + 4
        logger.debug(" Set segment base to 0x%X", base)

    # Big ugly patch to deal with APP2 (or other) data coming before APP1
    fh.seek(0)
    # in theory, this could be insufficient since 64K is the maximum size--gd
    data = fh.read(base + 4000)
    # base = 2
    while True:
        logger.debug(" Segment base 0x%X", base)
        if data[base:base + 2] == b'\xFF\xE1':
            # APP1
            logger.debug("  APP1 at base 0x%X", base)
            logger.debug("  Length: 0x%X 0x%X", ord_(data[base + 2]), ord_(data[base + 3]))
            logger.debug("  Code: %s", data[base + 4:base + 8])
            if data[base + 4:base + 8] == b"Exif":
                logger.debug(
                    "  Decrement base by 2 to get to pre-segment header (for compatibility with later code)"
                )
                base -= 2
                break
            increment = increment_base(data, base)
            logger.debug(" Increment base by %s", increment)
            base += increment
        elif data[base:base + 2] == b'\xFF\xE0':
            # APP0
            logger.debug("  APP0 at base 0x%X", base)
            logger.debug("  Length: 0x%X 0x%X", ord_(data[base + 2]), ord_(data[base + 3]))
            logger.debug("  Code: %s", data[base + 4:base + 8])
            increment = increment_base(data, base)
            logger.debug(" Increment base by %s", increment)
            base += increment
        elif data[base:base + 2] == b'\xFF\xE2':
            # APP2
            logger.debug("  APP2 at base 0x%X", base)
            logger.debug("  Length: 0x%X 0x%X", ord_(data[base + 2]), ord_(data[base + 3]))
            logger.debug(" Code: %s", data[base + 4:base + 8])
            increment = increment_base(data, base)
            logger.debug(" Increment base by %s", increment)
            base += increment
        elif data[base:base + 2] == b'\xFF\xEE':
            # APP14
            logger.debug("  APP14 Adobe segment at base 0x%X", base)
            logger.debug("  Length: 0x%X 0x%X", ord_(data[base + 2]), ord_(data[base + 3]))
            logger.debug("  Code: %s", data[base + 4:base + 8])
            increment = increment_base(data, base)
            logger.debug(" Increment base by %s", increment)
            base += increment
            logger.debug("  There is useful EXIF-like data here, but we have no parser for it.")
        elif data[base:base + 2] == b'\xFF\xDB':
            logger.debug("  JPEG image data at base 0x%X No more segments are expected.", base)
            break
        elif data[base:base + 2] == b'\xFF\xD8':
            # APP12
            logger.debug("  FFD8 segment at base 0x%X", base)
            logger.debug(
                "  Got 0x%X 0x%X and %s instead", ord_(data[base]), ord_(data[base + 1]), data[4 + base:10 + base]
            )
            logger.debug("  Length: 0x%X 0x%X", ord_(data[base + 2]), ord_(data[base + 3]))
            logger.debug("  Code: %s", data[base + 4:base + 8])
            increment = increment_base(data, base)
            logger.debug("  Increment base by %s", increment)
            base += increment
        elif data[base:base + 2] == b'\xFF\xEC':
            # APP12
            logger.debug("  APP12 XMP (Ducky) or Pictureinfo segment at base 0x%X", base)
            logger.debug("  Got 0x%X and 0x%X instead", ord_(data[base]), ord_(data[base + 1]))
            logger.debug("  Length: 0x%X 0x%X", ord_(data[base + 2]), ord_(data[base + 3]))
            logger.debug("Code: %s", data[base + 4:base + 8])
            increment = increment_base(data, base)
            logger.debug("  Increment base by %s", increment)
            base += increment
            logger.debug(
                "  There is useful EXIF-like data here (quality, comment, copyright), "
                "but we have no parser for it."
            )
        else:
            try:
                increment = increment_base(data, base)
                logger.debug("  Got 0x%X and 0x%X instead", ord_(data[base]), ord_(data[base + 1]))
            except IndexError:
                raise InvalidExif("Unexpected/unhandled segment type or file content.")
            else:
                logger.debug("  Increment base by %s", increment)
                base += increment
    fh.seek(base + 12)
    if ord_(data[2 + base]) == 0xFF and data[6 + base:10 + base] == b'Exif':
        # detected EXIF header
        offset = fh.tell()
        endian = fh.read(1)
        #HACK TEST:  endian = 'M'
    elif ord_(data[2 + base]) == 0xFF and data[6 + base:10 + base + 1] == b'Ducky':
        # detected Ducky header.
        logger.debug(
            "EXIF-like header (normally 0xFF and code): 0x%X and %s",
            ord_(data[2 + base]), data[6 + base:10 + base + 1]
        )
        offset = fh.tell()
        endian = fh.read(1)
    elif ord_(data[2 + base]) == 0xFF and data[6 + base:10 + base + 1] == b'Adobe':
        # detected APP14 (Adobe)
        logger.debug(
            "EXIF-like header (normally 0xFF and code): 0x%X and %s",
            ord_(data[2 + base]), data[6 + base:10 + base + 1]
        )
        offset = fh.tell()
        endian = fh.read(1)
    else:
        # no EXIF information
        msg = "No EXIF header expected data[2+base]==0xFF and data[6+base:10+base]===Exif (or Duck)"
        msg += "Did get 0x%X and %s" % (ord_(data[2 + base]), data[6 + base:10 + base + 1])
        raise InvalidExif(msg)
    return offset, endian


def find_exif(fh: BinaryIO) -> Tuple[str, int, str]:
    fh.seek(0)
    data = fh.read(12)
    if data[0:2] in [b'II', b'MM']:
        file_type = FILE_TYPE_TIFF
        offset, endian = find_tiff_exif(fh)
    elif data[4:12] == b'ftypheic':
        file_type = FILE_TYPE_HEIC
        fh.seek(0)
        heic = HEICExifFinder(fh)
        offset, endian = heic.find_exif()
    elif data[0:4] == b'RIFF' and data[8:12] == b'WEBP':
        file_type = FILE_TYPE_WEBP
        offset, endian = find_webp_exif(fh)
    elif data[0:2] == b'\xFF\xD8':
        file_type = FILE_TYPE_JPEG
        offset, endian = find_jpeg_exif(fh, data)
    else:
        # file format not recognized
        raise ExifNotFound("File format not recognized.")

    endian_str = chr(ord_(endian[0]))
    logger.debug("Endian format is %s (%s)", endian_str, {
        'I': 'Intel',
        'M': 'Motorola',
        '\x01': 'Adobe Ducky',
        'd': 'XMP/Adobe unknown'
    }[endian_str])

    return file_type, offset, endian_str


def make_string(seq: Union[bytes, list]) -> str:
    """
    Don't throw an exception when given an out of range character.
    """
    string = ''
    for char in seq:
        # Screen out non-printing characters
        try:
            if 32 <= char < 256:
                string += chr(char)
        except TypeError:
            pass

    # If no printing chars
    if not string:
        if isinstance(seq, list):
            string = ''.join(map(str, seq))
            # Some UserComment lists only contain null bytes, nothing valueable to return
            if set(string) == {'0'}:
                return ''
        else:
            string = str(seq)

    # Clean undesirable characters on any end
    return string.strip(' \x00')


def make_string_uc(seq) -> str:
    """
    Special version to deal with the code in the first 8 bytes of a user comment.
    First 8 bytes gives coding system e.g. ASCII vs. JIS vs Unicode.
    """
    if not isinstance(seq, str):
        seq = seq[8:]
    # Of course, this is only correct if ASCII, and the standard explicitly
    # allows JIS and Unicode.
    return make_string(seq)


def get_gps_coords(tags: dict) -> tuple:

    lng_ref_tag_name = 'GPS GPSLongitudeRef'
    lng_tag_name = 'GPS GPSLongitude'
    lat_ref_tag_name = 'GPS GPSLatitudeRef'
    lat_tag_name = 'GPS GPSLatitude'

    # Check if these tags are present
    gps_tags = [lng_ref_tag_name, lng_tag_name, lat_tag_name, lat_tag_name]
    for tag in gps_tags:
        if not tag in tags.keys():
            return ()

    lng_ref_val = tags[lng_ref_tag_name].values
    lng_coord_val = [c.decimal() for c in tags[lng_tag_name].values]

    lat_ref_val = tags[lat_ref_tag_name].values
    lat_coord_val = [c.decimal() for c in tags[lat_tag_name].values]

    lng_coord = sum([c/60**i for i, c in enumerate(lng_coord_val)])
    lng_coord *= (-1) ** (lng_ref_val == 'W')

    lat_coord = sum([c/60**i for i, c in enumerate(lat_coord_val)])
    lat_coord *= (-1) ** (lat_ref_val == 'S')

    return (lat_coord, lng_coord)


def n2b(offset, length, endian) -> bytes:
    """Convert offset to bytes."""
    s = b''
    for _ in range(length):
        if endian == 'I':
            s += bytes([offset & 0xFF])
        else:
            s = bytes([offset & 0xFF]) + s
        offset = offset >> 8
    return s


def s2n(fh, initial_offset, offset, length: int, endian, signed=False) -> int:
    """
    Convert slice to integer, based on sign and endian flags.

    Usually this offset is assumed to be relative to the beginning of the
    start of the EXIF information.
    For some cameras that use relative tags, this offset may be relative
    to some other starting point.
    """
    # Little-endian if Intel, big-endian if Motorola
    fmt = '<' if endian == 'I' else '>'
    # Construct a format string from the requested length and signedness;
    # raise a ValueError if length is something silly like 3
    try:
        fmt += {
            (1, False): 'B',
            (1, True):  'b',
            (2, False): 'H',
            (2, True):  'h',
            (4, False): 'I',
            (4, True):  'i',
            (8, False): 'L',
            (8, True):  'l',
            }[(length, signed)]
    except KeyError:
        raise ValueError('unexpected unpacking length: %d' % length)
    fh.seek(initial_offset + offset)
    buf = fh.read(length)
    if buf:
        return struct.unpack(fmt, buf)[0]
    return 0


class Ratio(Fraction):
    """
    Ratio object that eventually will be able to reduce itself to lowest
    common denominator for printing.
    """

    # We're immutable, so use __new__ not __init__
    def __new__(cls, numerator=0, denominator=None):
        try:
            self = super(Ratio, cls).__new__(cls, numerator, denominator)
        except ZeroDivisionError:
            self = super(Ratio, cls).__new__(cls)
            self._numerator = numerator
            self._denominator = denominator
        return self

    def __repr__(self) -> str:
        return str(self)

    @property
    def num(self):
        return self.numerator

    @property
    def den(self):
        return self.denominator

    def decimal(self) -> float:
        return float(self)
