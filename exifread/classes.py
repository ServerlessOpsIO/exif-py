import re
import struct
from typing import BinaryIO, Dict, Any, List, Optional

from .exif_log import get_logger
from .utils import Ratio, determine_type, ord_
from .tags import EXIF_TAGS, DEFAULT_STOP_TAG, FIELD_TYPES, IGNORE_TAGS, SUBIFD_TAGS, IFD_TAG_MAP, makernote

logger = get_logger()

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


class IfdBase:
    """
    An Ifd
    """
    def __init__(
        self,
        file_handle: BinaryIO,
        ifd_name: str,
        parent_offset: int,
        ifd_offset: int,
        endian: str,
        fake_exif: int,
        strict: bool=False,
        detailed: bool=True,
        truncate_tags: bool=True
    ):
        self.file_handle = file_handle
        self.ifd_name = ifd_name

        self.parent_offset = parent_offset
        self.ifd_offset = ifd_offset
        self.endian = endian
        self.fake_exif = fake_exif

        self.strict = strict
        self.detailed = detailed
        self.truncate_tags = truncate_tags
        self.tags = {}  # type: Dict[str, Any]

        self.tag_dict = IFD_TAG_MAP.get(self.ifd_name, {})

        self.dump_ifd()

    # TODO Decode Olympus MakerNote tag based on offset within tag.
    # def _olympus_decode_tag(self, value, mn_tags):
    #     pass
    def _canon_decode_tag(self, value, mn_tags):
        """
        Decode Canon MakerNote tag based on offset within tag.

        See http://www.burren.cx/david/canon.html by David Burren
        """
        for i in range(1, len(value)):
            tag = mn_tags.get(i, ('Unknown', ))
            name = tag[0]
            if len(tag) > 1:
                val = tag[1].get(value[i], 'Unknown')
            else:
                val = value[i]
            try:
                logger.debug(" %s %s %s", i, name, hex(value[i]))
            except TypeError:
                logger.debug(" %s %s %s", i, name, value[i])

            # It's not a real IFD Tag but we fake one to make everybody happy.
            # This will have a "proprietary" type
            self.tags['MakerNote ' + name] = IfdTag(str(val), 0, 0, val, 0, 0)

    def _canon_decode_camera_info(self, camera_info_tag):
        """
        Decode the variable length encoded camera info section.
        """
        model = self.tags.get('Image Model', None)
        if not model:
            return
        model = str(model.values)

        camera_info_tags = None
        for (model_name_re, tag_desc) in makernote.canon.CAMERA_INFO_MODEL_MAP.items():
            if re.search(model_name_re, model):
                camera_info_tags = tag_desc
                break
        else:
            return

        # We are assuming here that these are all unsigned bytes (Byte or
        # Unknown)
        if camera_info_tag.field_type not in (1, 7):
            return
        camera_info = struct.pack('<%dB' % len(camera_info_tag.values), *camera_info_tag.values)

        # Look for each data value and decode it appropriately.
        for offset, tag in camera_info_tags.items():
            tag_format = tag[1]
            tag_size = struct.calcsize(tag_format)
            if len(camera_info) < offset + tag_size:
                continue
            packed_tag_value = camera_info[offset:offset + tag_size]
            tag_value = struct.unpack(tag_format, packed_tag_value)[0]

            tag_name = tag[0]
            if len(tag) > 2:
                if callable(tag[2]):
                    tag_value = tag[2](tag_value)
                else:
                    tag_value = tag[2].get(tag_value, tag_value)
            logger.debug(" %s %s", tag_name, tag_value)

            self.tags['MakerNote ' + tag_name] = IfdTag(str(tag_value), 0, 0, tag_value, 0, 0)

    def _process_field(self, tag_name, count, field_type, type_length, offset):
        values = []
        signed = (field_type in [6, 8, 9, 10])
        # XXX investigate
        # some entries get too big to handle could be malformed
        # file or problem with self.s2n
        if count < 1000:
            for _ in range(count):
                if field_type in (5, 10):
                    # a ratio
                    value = Ratio(
                        s2n(self.file_handle, self.parent_offset, offset, 4, self.endian, signed),
                        s2n(self.file_handle, self.parent_offset, offset + 4, 4, self.endian, signed)
                    )
                elif field_type in (11, 12):
                    # a float or double
                    unpack_format = ''
                    if self.endian == 'I':
                        unpack_format += '<'
                    else:
                        unpack_format += '>'
                    if field_type == 11:
                        unpack_format += 'f'
                    else:
                        unpack_format += 'd'
                    self.file_handle.seek(self.parent_offset + offset)
                    byte_str = self.file_handle.read(type_length)
                    value = struct.unpack(unpack_format, byte_str)
                else:
                    value = s2n(self.file_handle, self.parent_offset, offset, type_length, self.endian, signed)
                values.append(value)
                offset = offset + type_length
        # The test above causes problems with tags that are
        # supposed to have long values! Fix up one important case.
        elif tag_name in ('MakerNote', makernote.canon.CAMERA_INFO_TAG_NAME):
            for _ in range(count):
                value = s2n(self.file_handle, self.parent_offset, offset, type_length, self.endian, signed)
                values.append(value)
                offset = offset + type_length
        return values

    def _process_field2(self, ifd_name, tag_name, count, offset):
        values = ''
        # special case: null-terminated ASCII string
        # XXX investigate
        # sometimes gets too big to fit in int value
        if count != 0:  # and count < (2**31):  # 2E31 is hardware dependent. --gd
            file_position = self.parent_offset + offset
            try:
                self.file_handle.seek(file_position)
                values = self.file_handle.read(count)

                # Drop any garbage after a null.
                values = values.split(b'\x00', 1)[0]
                if isinstance(values, bytes):
                    try:
                        values = values.decode('utf-8')
                    except UnicodeDecodeError:
                        logger.warning('Possibly corrupted field %s in %s IFD', tag_name, ifd_name)
            except OverflowError:
                logger.warning('OverflowError at position: %s, length: %s', file_position, count)
                values = ''
            except MemoryError:
                logger.warning('MemoryError at position: %s, length: %s', file_position, count)
                values = ''
        return values

    def _process_tag(self, ifd, ifd_name: str, tag_entry, entry, tag: int, tag_name, relative, stop_tag) -> None:
        field_type = s2n(self.file_handle, self.parent_offset, entry + 2, 2, self.endian)

        # unknown field type
        if not 0 < field_type < len(FIELD_TYPES):
            if not self.strict:
                return
            raise ValueError('Unknown type %d in tag 0x%04X' % (field_type, tag))

        type_length = FIELD_TYPES[field_type][0]
        count = s2n(self.file_handle, self.parent_offset, entry + 4, 4, self.endian)
        # Adjust for tag id/type/count (2+2+4 bytes)
        # Now we point at either the data or the 2nd level offset
        offset = entry + 8

        # If the value fits in 4 bytes, it is inlined, else we
        # need to jump ahead again.
        if count * type_length > 4:
            # offset is not the value; it's a pointer to the value
            # if relative we set things up so s2n will seek to the right
            # place when it adds self.offset.  Note that this 'relative'
            # is for the Nikon type 3 makernote.  Other cameras may use
            # other relative offsets, which would have to be computed here
            # slightly differently.
            if relative:
                tmp_offset = s2n(self.file_handle, self.parent_offset, offset, 4, self.endian)
                offset = tmp_offset + ifd - 8
                if self.fake_exif:
                    offset += 18
            else:
                offset = s2n(self.file_handle, self.parent_offset, offset, 4, self.endian)

        field_offset = offset
        values = None
        if field_type == 2:
            values = self._process_field2(ifd_name, tag_name, count, offset)
        else:
            values = self._process_field(tag_name, count, field_type, type_length, offset)

        # now 'values' is either a string or an array
        # TODO: use only one type
        if count == 1 and field_type != 2:
            printable = str(values[0])
        elif count > 50 and len(values) > 20 and not isinstance(values, str):
            if self.truncate_tags:
                printable = str(values[0:20])[0:-1] + ', ... ]'
            else:
                printable = str(values[0:-1])
        else:
            printable = str(values)

        # compute printable version of values
        if tag_entry:
            # optional 2nd tag element is present
            if len(tag_entry) != 1:
                if callable(tag_entry[1]):
                    # call mapping function
                    printable = tag_entry[1](values)

                elif isinstance(values, list):
                    # A list can be a list of the same type of value or a list of values with a
                    # different meaning by position.

                    pretty_values = []
                    if isinstance(tag_entry[1], list):
                        for _i in range(len(values)):
                            pretty_values.append(tag_entry[1][_i].get(values[_i], repr(values[_i])))
                    else:
                        for val in values:
                            pretty_values.append(tag_entry[1].get(val, repr(val)))

                    # FIXME: with the exception of ASCII fields `values` will always be a list.
                    # We have no way of knowing if the field is a single value or list of
                    # values. Also not sure if we know the difference between an empty list and
                    # an empty field value. We just do our best here.
                    if len(pretty_values) > 1:
                        printable = str(pretty_values)
                    elif len(pretty_values) == 1:
                        printable = str(pretty_values[0])
                    else:
                        printable = ''

                else:
                    # NOTE: We shouldn't make it here. This would mean we received an ASCII
                    # value to be used in a lookup table it is possible.
                    printable = tag_entry[1].get(val, repr(values))

        self.tags[tag_name] = IfdTag(
            printable, tag, field_type, values, field_offset, count * type_length
        )
        tag_value = repr(self.tags[tag_name])
        logger.debug(' %s: %s', tag_name, tag_value)

    def dump_ifd(self, ifd_offset: int=None, ifd_name: str=None, tag_dict: dict=None, relative: int=0, stop_tag: str=DEFAULT_STOP_TAG) -> None:
        """Populate IFD tags."""

        if ifd_offset is None:
            ifd_offset = self.ifd_offset
        if ifd_name is None:
            ifd_name = self.ifd_name
        if tag_dict is None:
            tag_dict = self.tag_dict

        try:
            entries = s2n(self.file_handle, self.parent_offset, ifd_offset, 2, self.endian)
        except TypeError:
            logger.warning('Possibly corrupted IFD: %s', ifd_offset)
            return

        for i in range(entries):
            # entry is index of start of this IFD in the file
            entry = ifd_offset + 2 + 12 * i
            tag = s2n(self.file_handle, self.parent_offset, entry, 2, self.endian)

            # get tag name early to avoid errors, help debug
            tag_entry = tag_dict.get(tag)
            if tag_entry:
                tag_name = tag_entry[0]
            else:
                tag_name = 'Tag 0x%04X' % tag

            # ignore certain tags for faster processing
            if not (not self.detailed and tag in IGNORE_TAGS):
                self._process_tag(ifd_offset, ifd_name, tag_entry, entry, tag, tag_name, relative, stop_tag)

            if tag_name == stop_tag:
                break


class Ifd(IfdBase):
    """
    An IFD
    """
    def __init__(
        self,
        file_handle: BinaryIO,
        ifd_name: str,
        parent_offset: int,
        ifd_offset: int,
        endian: str,
        fake_exif: int,
        strict: bool=False,
        detailed: bool=True,
        truncate_tags: bool=True
    ):
        super().__init__(
            file_handle,
            ifd_name,
            parent_offset,
            ifd_offset,
            endian,
            fake_exif,
            strict,
            detailed,
            truncate_tags
        )

        self.sub_ifds: List[Optional[SubIfd]] = []
        self.dump_sub_ifds()

    def dump_makernotes(self) -> None:
        """
        Decode all the camera-specific MakerNote formats

        Note is the data that comprises this MakerNote.
        The MakerNote will likely have pointers in it that point to other
        parts of the file. We'll use self.offset as the starting point for
        most of those pointers, since they are relative to the beginning
        of the file.
        If the MakerNote is in a newer format, it may use relative addressing
        within the MakerNote. In that case we'll use relative addresses for
        the pointers.
        As an aside: it's not just to be annoying that the manufacturers use
        relative offsets.  It's so that if the makernote has to be moved by the
        picture software all of the offsets don't have to be adjusted.  Overall,
        this is probably the right strategy for makernotes, though the spec is
        ambiguous.
        The spec does not appear to imagine that makernotes would
        follow EXIF format internally.  Once they did, it's ambiguous whether
        the offsets should be from the header at the start of all the EXIF info,
        or from the header at the start of the makernote.

        TODO: look into splitting this up
        """
        note = self.tags['EXIF MakerNote']

        # Some apps use MakerNote tags but do not use a format for which we
        # have a description, so just do a raw dump for these.
        make = self.tags['Image Make'].printable

        # Nikon
        # The maker note usually starts with the word Nikon, followed by the
        # type of the makernote (1 or 2, as a short).  If the word Nikon is
        # not at the start of the makernote, it's probably type 2, since some
        # cameras work that way.
        if 'NIKON' in make:
            if note.values[0:7] == [78, 105, 107, 111, 110, 0, 1]:
                logger.debug('Looks like a type 1 Nikon MakerNote.')
                self.dump_ifd(note.field_offset + 8, 'MakerNote',
                              tag_dict=makernote.nikon.TAGS_OLD)
            elif note.values[0:7] == [78, 105, 107, 111, 110, 0, 2]:
                logger.debug('Looks like a labeled type 2 Nikon MakerNote')
                if note.values[12:14] != [0, 42] and note.values[12:14] != [42, 0]:
                    raise ValueError('Missing marker tag 42 in MakerNote.')
                    # skip the Makernote label and the TIFF header
                self.dump_ifd(note.field_offset + 10 + 8, 'MakerNote',
                              tag_dict=makernote.nikon.TAGS_NEW, relative=1)
            else:
                # E99x or D1
                logger.debug('Looks like an unlabeled type 2 Nikon MakerNote')
                self.dump_ifd(note.field_offset, 'MakerNote',
                              tag_dict=makernote.nikon.TAGS_NEW)
            return

        # Olympus
        if make.startswith('OLYMPUS'):
            self.dump_ifd(note.field_offset + 8, 'MakerNote', tag_dict=makernote.olympus.TAGS)
            # TODO
            #for i in (('MakerNote Tag 0x2020', makernote.OLYMPUS_TAG_0x2020),):
            #    self.decode_olympus_tag(self.tags[i[0]].values, i[1])
            #return

        # Casio
        if 'CASIO' in make or 'Casio' in make:
            self.dump_ifd(note.field_offset, 'MakerNote',
                          tag_dict=makernote.casio.TAGS)
            return

        # Fujifilm
        if make == 'FUJIFILM':
            # bug: everything else is "Motorola" endian, but the MakerNote
            # is "Intel" endian
            endian = self.endian
            self.endian = 'I'
            # bug: IFD offsets are from beginning of MakerNote, not
            # beginning of file header
            offset = self.parent_offset
            self.parent_offset += note.field_offset
            # process note with bogus values (note is actually at offset 12)
            self.dump_ifd(12, 'MakerNote', tag_dict=makernote.fujifilm.TAGS)
            # reset to correct values
            self.endian = endian
            self.parent_offset = offset
            return

        # Apple
        if make == 'Apple' and note.values[0:10] == [65, 112, 112, 108, 101, 32, 105, 79, 83, 0]:
            offset = self.parent_offset
            self.parent_offset += note.field_offset + 14
            self.dump_ifd(0, 'MakerNote', tag_dict=makernote.apple.TAGS)
            self.parent_offset = offset
            return

        # Canon
        if make == 'Canon':
            self.dump_ifd(note.field_offset, 'MakerNote',
                          tag_dict=makernote.canon.TAGS)

            for i in (('MakerNote Tag 0x0001', makernote.canon.CAMERA_SETTINGS),
                      ('MakerNote Tag 0x0002', makernote.canon.FOCAL_LENGTH),
                      ('MakerNote Tag 0x0004', makernote.canon.SHOT_INFO),
                      ('MakerNote Tag 0x0026', makernote.canon.AF_INFO_2),
                      ('MakerNote Tag 0x0093', makernote.canon.FILE_INFO)):
                if i[0] in self.tags:
                    logger.debug('Canon %s', i[0])
                    self._canon_decode_tag(self.tags[i[0]].values, i[1])
                    del self.tags[i[0]]
            if makernote.canon.CAMERA_INFO_TAG_NAME in self.tags:
                tag = self.tags[makernote.canon.CAMERA_INFO_TAG_NAME]
                logger.debug('Canon CameraInfo')
                self._canon_decode_camera_info(tag)
                del self.tags[makernote.canon.CAMERA_INFO_TAG_NAME]
            return

    def dump_sub_ifds(self, ifd_offset: int=None, ifd_name: str=None, tag_dict: dict=None, relative: int=0, stop_tag: str=DEFAULT_STOP_TAG) -> None:
        """Populate SubIFDs."""
        for t in SUBIFD_TAGS:
            tag_entry = SUBIFD_TAGS.get(t)
            tag = self.tags.get(t)
            if tag is not None and tag_entry is not None:
                try:
                    for value in tag.values:
                        logger.debug('%s SubIFD at offset %d:', tag_entry[0], value)
                        self.sub_ifds.append(
                            SubIfd(
                                self.file_handle,
                                tag_entry[0],
                                self.parent_offset,
                                value,
                                self.endian,
                                self.fake_exif,
                                self,
                                self.strict,
                                self.detailed,
                                self.truncate_tags
                            )
                        )
                except IndexError:
                    logger.warning('No values found for %s SubIFD', tag_entry[0])


class SubIfd(IfdBase):
    """
    A SubIfd
    """
    def __init__(
        self,
        file_handle: BinaryIO,
        ifd_name: str,
        parent_offset: int,
        ifd_offset: int,
        endian: str,
        fake_exif: int,
        parent_ifd: Ifd,
        strict: bool=False,
        detailed: bool=True,
        truncate_tags: bool=True
    ):
        super().__init__(
            file_handle,
            ifd_name,
            parent_offset,
            ifd_offset,
            endian,
            fake_exif,
            strict,
            detailed,
            truncate_tags
        )

        self.parent_ifd = parent_ifd


class IfdTag:
    """
    Eases dealing with tags.
    """
    def __init__(self, printable: str, tag: int, field_type: int, values,
                 field_offset: int, field_length: int):
        # printable version of data
        self.printable = printable
        # tag ID number
        self.tag = tag
        # field type as index into FIELD_TYPES
        self.field_type = field_type
        # offset of start of field in bytes from beginning of IFD
        self.field_offset = field_offset
        # length of data field in bytes
        self.field_length = field_length
        # either string, bytes or list of data items
        # TODO: sort out this type mess!
        self.values = values

    def __str__(self) -> str:
        return self.printable

    def __repr__(self) -> str:
        try:
            tag = '(0x%04X) %s=%s @ %d' % (
                self.tag,
                FIELD_TYPES[self.field_type][2],
                self.printable,
                self.field_offset
            )
        except TypeError:
            tag = '(%s) %s=%s @ %s' % (
                str(self.tag),
                FIELD_TYPES[self.field_type][2],
                self.printable,
                str(self.field_offset)
            )
        return tag


class IfdTagValue:
    """
    IFD Tag value
    """
    pass


class ExifHeader:
    """
    Handle an EXIF header.
    """
    def __init__(self, file_handle: BinaryIO, strict: bool, detailed=True, truncate_tags=True):
        self.file_handle = file_handle

        # FIXME: Can we deimplify this?
        offset, endian, fake_exif = determine_type(self.file_handle)
        self.offset = offset
        self.endian = chr(ord_(endian[0]))
        self.fake_exif = fake_exif

        self.strict = strict
        self.detailed = detailed
        self.truncate_tags = truncate_tags
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
            ifd = Ifd(self.file_handle, ifd_name, self.offset, ifd_offset,
                      self.endian, self.fake_exif, self.strict, self.detailed,
                      self.truncate_tags)
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
        self.tags['Image ApplicationNotes'] = IfdTag('\n'.join(cleaned), 0, 1, xmp_bytes, 0, 0)
