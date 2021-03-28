import re
import struct
from typing import BinaryIO, Dict, Any, List, Optional, Union

from .exif_log import get_logger
from .ifd import Ifd, IfdTag
from .utils import Ratio, find_exif, ord_, n2b, s2n
from .tags import EXIF_TAGS, DEFAULT_STOP_TAG, FIELD_TYPES, SUBIFD_TAGS, IFD_TAG_MAP, makernote

logger = get_logger()

class ExifHeader:
    """
    Handle an EXIF header.
    """
    def __init__(self, file_handle: BinaryIO):
        self.file_handle = file_handle

        self.file_type, self.offset, self.endian = find_exif(self.file_handle)

        # TODO: get rid of 'Any' type
        self.tags = {}  # type: Dict[str, Any]

    def _first_ifd(self) -> int:
        """Return first IFD."""
        return s2n(self.file_handle, self.offset, 4, 4, self.endian)

    def _list_header_ifd_offsets(self) -> List[int]:
        """Return the list of IFDs in the header."""
        i = self._first_ifd()
        ifds = []
        while i:
            ifds.append(i)
            i = self._next_ifd(i)
        return ifds

    def _next_ifd(self, ifd) -> int:
        """Return the pointer to next IFD."""
        entries = s2n(self.file_handle, self.offset, ifd, 2, self.endian)
        next_ifd = s2n(self.file_handle, self.offset, ifd + 2 + 12 * entries, 4, self.endian)
        if next_ifd == ifd:
            return 0
        return next_ifd

    def extract_tiff_thumbnail(self, thumb_ifd: int) -> None:
        """
        Extract uncompressed TIFF thumbnail.

        Take advantage of the pre-existing layout in the thumbnail IFD as
        much as possible
        """
        thumb = self.tags.get('Thumbnail Compression')
        if not thumb or thumb.printable != 'Uncompressed TIFF':
            return

        entries = s2n(self.file_handle, self.offset, thumb_ifd, 2, self.endian)
        # this is header plus offset to IFD ...
        if self.endian == 'M':
            tiff = b'MM\x00*\x00\x00\x00\x08'
        else:
            tiff = b'II*\x00\x08\x00\x00\x00'
            # ... plus thumbnail IFD data plus a null "next IFD" pointer
        self.file_handle.seek(self.offset + thumb_ifd)
        tiff += self.file_handle.read(entries * 12 + 2) + b'\x00\x00\x00\x00'

        # fix up large value offset pointers into data area
        for i in range(entries):
            entry = thumb_ifd + 2 + 12 * i
            tag = s2n(self.file_handle, self.offset, entry, 2, self.endian)
            field_type = s2n(self.file_handle, self.offset, entry + 2, 2, self.endian)
            type_length = FIELD_TYPES[field_type][0]
            count = s2n(self.file_handle, self.offset, entry + 4, 4, self.endian)
            old_offset = s2n(self.file_handle, self.offset, entry + 8, 4, self.endian)
            # start of the 4-byte pointer area in entry
            ptr = i * 12 + 18
            # remember strip offsets location
            if tag == 0x0111:
                strip_off = ptr
                strip_len = count * type_length
                # is it in the data area?
            if count * type_length > 4:
                # update offset pointer (nasty "strings are immutable" crap)
                # should be able to say "tiff[ptr:ptr+4]=newoff"
                newoff = len(tiff)
                tiff = tiff[:ptr] + n2b(newoff, 4, self.endian) + tiff[ptr + 4:]
                # remember strip offsets location
                if tag == 0x0111:
                    strip_off = newoff
                    strip_len = 4
                # get original data and store it
                self.file_handle.seek(self.offset + old_offset)
                tiff += self.file_handle.read(count * type_length)

        # add pixel strips and update strip offset info
        old_offsets = self.tags['Thumbnail StripOffsets'].values
        old_counts = self.tags['Thumbnail StripByteCounts'].values
        for i, old_offset in enumerate(old_offsets):
            # update offset pointer (more nasty "strings are immutable" crap)
            offset = n2b(len(tiff), strip_len, self.endian)
            tiff = tiff[:strip_off] + offset + tiff[strip_off + strip_len:]
            strip_off += strip_len
            # add pixel strip to end
            self.file_handle.seek(self.offset + old_offset)
            tiff += self.file_handle.read(old_counts[i])

        self.tags['TIFFThumbnail'] = tiff

    def extract_jpeg_thumbnail(self) -> None:
        """
        Extract JPEG thumbnail.

        (Thankfully the JPEG data is stored as a unit.)
        """
        thumb_offset = self.tags.get('Thumbnail JPEGInterchangeFormat')
        if thumb_offset:
            self.file_handle.seek(self.offset + thumb_offset.values[0])
            size = self.tags['Thumbnail JPEGInterchangeFormatLength'].values[0]
            self.tags['JPEGThumbnail'] = self.file_handle.read(size)

        # Sometimes in a TIFF file, a JPEG thumbnail is hidden in the MakerNote
        # since it's not allowed in a uncompressed TIFF IFD
        if 'JPEGThumbnail' not in self.tags:
            thumb_offset = self.tags.get('MakerNote JPEGThumbnail')
            if thumb_offset:
                self.file_handle.seek(self.offset + thumb_offset.values[0])
                self.tags['JPEGThumbnail'] = self.file_handle.read(thumb_offset.field_length)

    def list_ifds(self) -> List[Ifd]:
        """Return the list of IFDs in the header."""
        ifds = []
        ctr = 0
        for ifd_offset in self._list_header_ifd_offsets():
            if ctr == 0:
                ifd_name = 'IFD0'
            elif ctr == 1:
                ifd_name = 'Thumbnail'
            ifd = Ifd(
                self.file_handle,
                self.file_type,
                ifd_name,
                self.offset,
                ifd_offset,
                self.endian,
            )
            ifds.append(ifd)
            ctr += 1
        return ifds

    def parse_xmp(self, xmp_bytes: bytes):
        """Adobe's Extensible Metadata Platform, just dump the pretty XML."""

        import xml.dom.minidom  # pylint: disable=import-outside-toplevel

        logger.debug('XMP cleaning data')

        # Pray that it's encoded in UTF-8
        # TODO: allow user to specifiy encoding
        xmp_string = xmp_bytes.decode('utf-8')

        pretty = xml.dom.minidom.parseString(xmp_string).toprettyxml()
        cleaned = []
        for line in pretty.splitlines():
            if line.strip():
                cleaned.append(line)
        self.tags['Image ApplicationNotes'] = IfdTag(0, 1, '\n'.join(cleaned), 0, 0)
