import re
import struct
from typing import BinaryIO, Dict, Any, List, Optional, Union
from xml.dom.minidom import parseString


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
        self._file_handle = file_handle
        self._offset: int
        self._endian: str
        self.file_type: str

        self.file_type, self._offset, self._endian = find_exif(self._file_handle)
        self.ifds: List[Ifd] = self._list_ifds()

    def __str__(self) -> str:
        return '{} EXIF Header @ {}'.format(self.file_type, self._offset)

    def __repr__(self) -> str:
        return '{} EXIF Header @ {}'.format(self.file_type, self._offset)

    def _first_ifd(self) -> int:
        """Return first IFD."""
        return s2n(self._file_handle, self._offset, 4, 4, self._endian)

    def _list_header_ifd_offsets(self) -> List[int]:
        """Return the list of IFDs in the header."""
        i = self._first_ifd()
        ifds = []
        while i:
            ifds.append(i)
            i = self._next_ifd(i)
        return ifds

    def _list_ifds(self) -> List[Ifd]:
        """Return the list of IFDs in the header."""
        ifds = []
        ctr = 0
        for ifd_offset in self._list_header_ifd_offsets():
            if ctr == 0:
                ifd_name = 'IFD0'
            elif ctr == 1:
                ifd_name = 'Thumbnail'

            logger.debug('IFD %d (%s) at offset %s:', ctr, ifd_name, ifd_offset)
            ifd = Ifd(
                self._file_handle,
                self.file_type,
                ifd_name,
                self._offset,
                ifd_offset,
                self._endian,
            )
            ifds.append(ifd)
            ctr += 1
        return ifds

    def _next_ifd(self, ifd) -> int:
        """Return the pointer to next IFD."""
        entries = s2n(self._file_handle, self._offset, ifd, 2, self._endian)
        next_ifd = s2n(self._file_handle, self._offset, ifd + 2 + 12 * entries, 4, self._endian)
        if next_ifd == ifd:
            return 0
        return next_ifd

    @property
    def _tags(self) -> Dict[str, Dict]:
        """
        Private copy of all tags.

        Used for operations required to be done at the EXIF header level.
        eg. Extracting thumbnails
        """
        tags = {}
        for _ifd in self.ifds:
            ifd_name = _ifd.ifd_name
            tags[ifd_name] = _ifd.get_tags()

        return tags


    def get_tags(self):
        """
        Get all tags from IFDs
        """
        return self._tags

    def extract_tiff_thumbnail(self, thumb_ifd: int) -> None:
        """
        Extract uncompressed TIFF thumbnail.

        Take advantage of the pre-existing layout in the thumbnail IFD as
        much as possible
        """
        thumb = self._tags['Thumbnail']['Compression']
        if not thumb or thumb.printable != 'Uncompressed TIFF':
            return

        entries = s2n(self._file_handle, self._offset, thumb_ifd, 2, self._endian)
        # this is header plus offset to IFD ...
        if self._endian == 'M':
            tiff = b'MM\x00*\x00\x00\x00\x08'
        else:
            tiff = b'II*\x00\x08\x00\x00\x00'
            # ... plus thumbnail IFD data plus a null "next IFD" pointer
        self._file_handle.seek(self._offset + thumb_ifd)
        tiff += self._file_handle.read(entries * 12 + 2) + b'\x00\x00\x00\x00'

        # fix up large value offset pointers into data area
        for i in range(entries):
            entry = thumb_ifd + 2 + 12 * i
            tag = s2n(self._file_handle, self._offset, entry, 2, self._endian)
            field_type = s2n(self._file_handle, self._offset, entry + 2, 2, self._endian)
            type_length = FIELD_TYPES[field_type][0]
            count = s2n(self._file_handle, self._offset, entry + 4, 4, self._endian)
            old_offset = s2n(self._file_handle, self._offset, entry + 8, 4, self._endian)
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
                tiff = tiff[:ptr] + n2b(newoff, 4, self._endian) + tiff[ptr + 4:]
                # remember strip offsets location
                if tag == 0x0111:
                    strip_off = newoff
                    strip_len = 4
                # get original data and store it
                self._file_handle.seek(self._offset + old_offset)
                tiff += self._file_handle.read(count * type_length)

        # add pixel strips and update strip offset info
        old_offsets = self._tags['Thumbnail']['StripOffsets'].values
        old_counts = self._tags['Thumbnail']['StripByteCounts'].values
        for i, old_offset in enumerate(old_offsets):
            # update offset pointer (more nasty "strings are immutable" crap)
            offset = n2b(len(tiff), strip_len, self._endian)
            tiff = tiff[:strip_off] + offset + tiff[strip_off + strip_len:]
            strip_off += strip_len
            # add pixel strip to end
            self._file_handle.seek(self._offset + old_offset)
            tiff += self._file_handle.read(old_counts[i])

        self._tags['TIFFThumbnail'] = tiff

    def extract_jpeg_thumbnail(self) -> None:
        """
        Extract JPEG thumbnail.

        (Thankfully the JPEG data is stored as a unit.)
        """
        thumb_offset = self._tags['Thumbnail'].get('JPEGInterchangeFormat')
        if thumb_offset:
            self._file_handle.seek(self._offset + thumb_offset.values[0])
            size = self._tags['Thumbnail']['JPEGInterchangeFormatLength'].values[0]
            self._tags['JPEGThumbnail'] = self._file_handle.read(size)

        # Sometimes in a TIFF file, a JPEG thumbnail is hidden in the MakerNote
        # since it's not allowed in a uncompressed TIFF IFD
        if 'JPEGThumbnail' not in self._tags:
            thumb_offset = self._tags.get('MakerNote JPEGThumbnail')
            if thumb_offset:
                self._file_handle.seek(self._offset + thumb_offset.values[0])
                self._tags['JPEGThumbnail'] = self._file_handle.read(thumb_offset.field_length)

    def parse_xmp(self, xmp_bytes: bytes):
        """Adobe's Extensible Metadata Platform, just dump the pretty XML."""
        xmp_bytes = b''
        xmp_tag = self._tags['IFD0']['ApplicationNotes']
        if xmp_tag:
            logger.debug('XMP present in Exif')
            xmp_bytes = bytes(xmp_tag.values)

        if xmp_bytes:
            # Pray that it's encoded in UTF-8
            # TODO: allow user to specifiy encoding

            xmp_string = xmp_bytes.decode('utf-8')

            pretty = parseString(xmp_string).toprettyxml()
            cleaned = []
            for line in pretty.splitlines():
                if line.strip():
                    cleaned.append(line)
            self._tags['Image ApplicationNotes'] = IfdTag(0, 1, '\n'.join(cleaned), 0, 0)
