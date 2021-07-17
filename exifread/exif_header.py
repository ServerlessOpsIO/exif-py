from io import BytesIO
from typing import BinaryIO, Dict, List, Optional, Tuple, Union
from xml.dom.minidom import parseString


from .exif_log import get_logger
from .ifd import IfdBase, Ifd, IfdTag, MakerNote
from .utils import find_exif, n2b, s2n
from .tags import FIELD_TYPES
from .thumbnail import Thumbnail, THUMBNAIL_UNKNOWN_COMPRESSION, THUMBNAIL_UNKNOWN_FILE_TYPE

logger = get_logger()

class ExifHeader:
    """
    Handle an EXIF header.
    """
    def __init__(self, file_handle: BinaryIO):
        self._file_handle = BytesIO(file_handle.read())
        self._offset: int
        self._endian: str
        self.file_type: str

        self.file_type, self._offset, self._endian = find_exif(self._file_handle)
        self.ifds: List[Ifd] = self._list_ifds()
        self._image_ifds, self._thumbnail_ifds = self._find_image_ifds()

    def __str__(self) -> str:
        return '{} EXIF Header @ {}'.format(self.file_type, self._offset)

    def __repr__(self) -> str:
        return '<{}.{} {} offset={}, endian={} at {}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.file_type,
            self._offset,
            self._endian,
            hex(id(self))
        )

    def _first_ifd(self) -> int:
        """Return first IFD."""
        return s2n(self._file_handle, self._offset, 4, 4, self._endian)

    def _find_image_ifds(self) -> Tuple[List[IfdBase], List[IfdBase]]:
        """Return IFDs containing image data"""
        image_ifds: List[IfdBase] = []
        thumbnail_ifds: List[IfdBase] = []

        for _i in self.ifds:
            if _i.tags.get('Compression'):
                sub_file_type = _i.tags.get('SubfileType')
                if sub_file_type:
                    if sub_file_type.printable == 'Reduced-resolution image':
                        thumbnail_ifds.append(_i)
                    elif sub_file_type.printable == 'Full-resolution image':
                        image_ifds.append(_i)
                    else:
                        logger.debug('Unrecognized SubFileType')
                else:
                    thumbnail_ifds.append(_i)

            for _s in _i.sub_ifds:
                if _s.tags.get('Compression'):
                    sub_file_type = _s.tags.get('SubfileType')
                    if sub_file_type:
                        if sub_file_type.printable == 'Reduced-resolution image':
                            thumbnail_ifds.append(_s)
                        elif sub_file_type.printable == 'Full-resolution image':
                            image_ifds.append(_s)
                        else:
                            logger.debug('Unrecognized SubFileType')
                    else:
                        thumbnail_ifds.append(_s)

        return image_ifds, thumbnail_ifds

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
            ifd_name = 'IFD' + str(ctr)

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
            ifd_name = _ifd.name
            tags[ifd_name] = _ifd.get_tags()

        return tags

    def get_tags(self):
        """
        Get all tags from IFDs
        """
        return self._tags

    @property
    def thumbnails(self) -> List[Thumbnail]:
        """
        Return all thumbnails
        """
        thumb_list = []
        for _thumb_ifd in self._thumbnail_ifds:
            if _thumb_ifd.tags.get('Compression') == 'Uncompressed':
                thumb = self._extract_tiff_thumbnail(_thumb_ifd)
            else:
                thumb = self._extract_jpeg_thumbnail(_thumb_ifd)

            if thumb is not None:
                thumb_list.append(thumb)

        return thumb_list

    def _extract_tiff_thumbnail(self, ifd: IfdBase) -> Optional[Thumbnail]:
        """
        Extract uncompressed TIFF thumbnail.

        Take advantage of the pre-existing layout in the thumbnail IFD as
        much as possible
        """
        file_type = ifd.tags.get('SubfileType')
        if file_type is not None:
            file_type_name = file_type.printable
        else:
            file_type_name = THUMBNAIL_UNKNOWN_FILE_TYPE

        compression = ifd.tags.get('Compression')
        if compression is not None:
            compression_name = compression.printable
        else:
            compression_name = THUMBNAIL_UNKNOWN_COMPRESSION

        if ifd.tags.get('StripOffsets') is not None:
            offset_name = 'StripOffsets'
            byte_count_name = 'StripByteCounts'
        elif ifd.tags.get('ThumbnailOffset') is not None:
            offset_name = 'ThumbnailOffset'
            byte_count_name = 'ThumbnailLength'
        else:
            logger.debug('Cannot find thumbnail offset tags in IFD {}'.format(ifd))

        entries = s2n(self._file_handle, self._offset, ifd.offset, 2, self._endian)
        # this is header plus offset to IFD ...
        if self._endian == 'M':
            tiff = b'MM\x00*\x00\x00\x00\x08'
        else:
            tiff = b'II*\x00\x08\x00\x00\x00'
            # ... plus thumbnail IFD data plus a null "next IFD" pointer
        self._file_handle.seek(self._offset + ifd.offset)
        tiff += self._file_handle.read(entries * 12 + 2) + b'\x00\x00\x00\x00'

        # fix up large value offset pointers into data area
        for i in range(entries):
            entry = ifd.offset + 2 + 12 * i
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
        old_offsets = ifd.tags.get(offset_name).values
        old_counts = ifd.tags.get(byte_count_name).values
        for i, old_offset in enumerate(old_offsets):
            # update offset pointer (more nasty "strings are immutable" crap)
            offset = n2b(len(tiff), strip_len, self._endian)
            tiff = tiff[:strip_off] + offset + tiff[strip_off + strip_len:]
            strip_off += strip_len
            # add pixel strip to end
            self._file_handle.seek(self._offset + old_offset)
            tiff += self._file_handle.read(old_counts[i])

        logger.debug('TIFF thumbnail found in {}'.format(ifd))
        return Thumbnail(file_type_name, compression_name, BytesIO(tiff), ifd)

    def _extract_jpeg_thumbnail(self, ifd: IfdBase) -> Optional[Thumbnail]:
        """
        Extract JPEG thumbnail.

        (Thankfully the JPEG data is stored as a unit.)
        """
        # FIXME: Need to handle when this does not exist
        if ifd.tags.get('StripOffsets') is not None:
            offset_name = 'StripOffsets'
            byte_count_name = 'StripByteCounts'
        elif ifd.tags.get('ThumbnailOffset') is not None:
            offset_name = 'ThumbnailOffset'
            byte_count_name = 'ThumbnailLength'
        else:
            logger.debug('Cannot find thumbnail offset tags in IFD {}'.format(ifd))

        thumb_offset = ifd.tags.get(offset_name)

        file_type = ifd.tags.get('SubfileType')
        if file_type is not None:
            file_type_name = file_type.printable
        else:
            file_type_name = THUMBNAIL_UNKNOWN_FILE_TYPE

        compression = ifd.tags.get('Compression')
        if compression is not None:
            compression_name = compression.printable
        else:
            compression_name = THUMBNAIL_UNKNOWN_COMPRESSION

        thumbnail: Union[Thumbnail, None]
        if thumb_offset:
            # FIXME: How should we handle most missing tags?
            self._file_handle.seek(self._offset + thumb_offset.values[0])
            size = ifd.tags.get(byte_count_name).values[0]
            thumb: bytes = self._file_handle.read(size)

            logger.debug('JPEG thumbnail found in {}'.format(ifd))
            # FIXME: Should we use the numeric EXIF values instead?
            thumbnail = Thumbnail(file_type_name, compression_name, BytesIO(thumb), ifd)
        else:
            thumbnail = None

        return thumbnail

    def _extract_makernote_thumbnail(self, makernote: MakerNote) -> Optional[Thumbnail]:
        """
        Extract thumbnail from Maker Notes.
        """
        thumbnail: Union[Thumbnail, None]
        # FIXME: This is actually Olympus only as far as known currently.
        #if 'JPEGThumbnail' not in self._tags:
        #    thumb_offset = self._tags.get('MakerNote JPEGThumbnail')
        #    if thumb_offset:
        #        self._file_handle.seek(self._offset + thumb_offset.values[0])
        #        self._tags['JPEGThumbnail'] = self._file_handle.read(thumb_offset.field_length)

        return None


    @property
    def image(self):
        pass

    def _extract_image(self):
        pass


    def parse_xmp(self) -> str:
        """Adobe's Extensible Metadata Platform, just dump the pretty XML."""
        cleaned_xmp = []

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
            for line in pretty.splitlines():
                if line.strip():
                    cleaned_xmp.append(line)
        return '\n'.join(cleaned_xmp)
