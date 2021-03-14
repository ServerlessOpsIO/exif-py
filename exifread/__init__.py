"""
Read Exif metadata from tiff and jpeg files.
"""
from typing import BinaryIO

from .exif_log import get_logger
from .classes import ExifHeader, Ifd
from .tags import DEFAULT_STOP_TAG
from .utils import determine_type
from .heic import HEICExifFinder

__version__ = '3.0.0'

logger = get_logger()


def _get_xmp(fh: BinaryIO) -> bytes:
    xmp_bytes = b''
    logger.debug('XMP not in Exif, searching file for XMP info...')
    xml_started = False
    xml_finished = False
    for line in fh:
        open_tag = line.find(b'<x:xmpmeta')
        close_tag = line.find(b'</x:xmpmeta>')
        if open_tag != -1:
            xml_started = True
            line = line[open_tag:]
            logger.debug('XMP found opening tag at line position %s', open_tag)
        if close_tag != -1:
            logger.debug('XMP found closing tag at line position %s', close_tag)
            line_offset = 0
            if open_tag != -1:
                line_offset = open_tag
            line = line[:(close_tag - line_offset) + 12]
            xml_finished = True
        if xml_started:
            xmp_bytes += line
        if xml_finished:
            break
    logger.debug('XMP Finished searching for info')
    return xmp_bytes


def process_file(fh: BinaryIO, stop_tag=DEFAULT_STOP_TAG,
                 details=True, strict=False, debug=False,
                 truncate_tags=True, auto_seek=True):
    """
    Process an image file (expects an open file object).

    This is the function that has to deal with all the arbitrary nasty bits
    of the EXIF standard.
    """

    if auto_seek:
        fh.seek(0)

    hdr = ExifHeader(fh, strict, details, truncate_tags)

    # deal with the EXIF info we found
    logger.debug("Endian format is %s (%s)", hdr.endian, {
        'I': 'Intel',
        'M': 'Motorola',
        '\x01': 'Adobe Ducky',
        'd': 'XMP/Adobe unknown'
    }[hdr.endian])

    ifd_list = hdr.list_header_ifd_offsets()
    thumb_ifd = 0
    ctr = 0
    for ifd in ifd_list:
        if ctr == 0:
            ifd_name = 'Image'
        elif ctr == 1:
            ifd_name = 'Thumbnail'
            thumb_ifd = ifd
        else:
            ifd_name = 'IFD %d' % ctr
        logger.debug('IFD %d (%s) at offset %s:', ctr, ifd_name, ifd)
        hdr.dump_ifd(ifd, ifd_name, stop_tag=stop_tag)
        ctr += 1
    # EXIF IFD
    exif_off = hdr.tags.get('Image ExifOffset')
    if exif_off:
        logger.debug('Exif SubIFD at offset %s:', exif_off.values[0])
        hdr.dump_ifd(exif_off.values[0], 'EXIF', stop_tag=stop_tag)

    # deal with MakerNote contained in EXIF IFD
    # (Some apps use MakerNote tags but do not use a format for which we
    # have a description, do not process these).
    if details and 'EXIF MakerNote' in hdr.tags and 'Image Make' in hdr.tags:
        hdr.decode_maker_note()

    # extract thumbnails
    if details and thumb_ifd:
        hdr.extract_tiff_thumbnail(thumb_ifd)
        hdr.extract_jpeg_thumbnail()

    # parse XMP tags (experimental)
    if debug and details:
        xmp_bytes = b''
        # Easy we already have them
        xmp_tag = hdr.tags.get('Image ApplicationNotes')
        if xmp_tag:
            logger.debug('XMP present in Exif')
            xmp_bytes = bytes(xmp_tag.values)
        # We need to look in the entire file for the XML
        else:
            xmp_bytes = _get_xmp(fh)
        if xmp_bytes:
            hdr.parse_xmp(xmp_bytes)
    return hdr.tags
