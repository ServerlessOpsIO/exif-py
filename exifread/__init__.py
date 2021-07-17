"""
Read Exif metadata from tiff and jpeg files.
"""
from typing import BinaryIO

from .exif_log import get_logger
from .exif_header import ExifHeader

__version__ = '3.0.0'

logger = get_logger()


def process_file(fh: BinaryIO):
    """
    Process an image file (expects an open file object).

    This is the function that has to deal with all the arbitrary nasty bits
    of the EXIF standard.
    """
    fh.seek(0)
    hdr = ExifHeader(fh)

    return hdr.get_tags()
