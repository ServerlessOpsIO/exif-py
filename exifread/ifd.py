import re
import struct
from typing import Any, BinaryIO, Dict, Any, List, Optional, Union

from .exif_log import get_logger
from .utils import Ratio, determine_type, ord_, s2n
from .tags import EXIF_TAGS, DEFAULT_STOP_TAG, FIELD_TYPES, SUBIFD_TAGS, IFD_TAG_MAP, makernote

logger = get_logger()

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
        tag_dict: dict,
        relative_tags: bool=False,
        truncate_tags: bool=True,
    ):
        self.file_handle = file_handle
        self.ifd_name = ifd_name

        self.parent_offset = parent_offset
        self.ifd_offset = ifd_offset
        self.endian = endian
        self.fake_exif = fake_exif
        self.tag_dict = tag_dict
        self.relative_tags = relative_tags

        self.truncate_tags = truncate_tags
        self.tags = {}  # type: Dict[str, Any]

        self._dump_ifd()

    # TODO Decode Olympus MakerNote tag based on offset within tag.
    # def _olympus_decode_tag(self, value, mn_tags):
    #     pass

    # FIXME: This should be done in IfdTag
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
            self.tags['MakerNote ' + name] = IfdTag(0, 0, val, 0, 0)

    # FIXME: This should be done in IfdTag
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

            self.tags['MakerNote ' + tag_name] = IfdTag(0, 0, tag_value, 0, 0)

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

    def _process_tag(self, ifd, ifd_name: str, tag_entry, entry, tag: int, tag_name, stop_tag, relative_tags) -> None:
        field_type = s2n(self.file_handle, self.parent_offset, entry + 2, 2, self.endian)

        # unknown field type
        if not 0 < field_type < len(FIELD_TYPES):
            return

        type_length = FIELD_TYPES[field_type][0]
        field_length = s2n(self.file_handle, self.parent_offset, entry + 4, 4, self.endian)
        # Adjust for tag id/type/count (2+2+4 bytes)
        # Now we point at either the data or the 2nd level offset
        offset = entry + 8

        # If the value fits in 4 bytes, it is inlined, else we
        # need to jump ahead again.
        if field_length * type_length > 4:
            # offset is not the value; it's a pointer to the value
            # if relative we set things up so s2n will seek to the right
            # place when it adds self.offset.  Note that this 'relative'
            # is for the Nikon type 3 makernote.  Other cameras may use
            # other relative offsets, which would have to be computed here
            # slightly differently.
            if relative_tags:
                tmp_offset = s2n(self.file_handle, self.parent_offset, offset, 4, self.endian)
                offset = tmp_offset + ifd - 8
                if self.fake_exif:
                    offset += 18
            else:
                offset = s2n(self.file_handle, self.parent_offset, offset, 4, self.endian)

        field_offset = offset
        values = None
        if field_type == 2:
            values = self._process_field2(ifd_name, tag_name, field_length, offset)
        else:
            values = self._process_field(tag_name, field_length, field_type, type_length, offset)

        self.tags[tag_name] = IfdTag(
            tag, field_type, values, field_offset, field_length * type_length, tag_entry, self.truncate_tags
        )
        tag_value = repr(self.tags[tag_name])
        logger.debug(' %s: %s', tag_name, tag_value)

    def _dump_ifd(self) -> None:
        """Populate IFD tags."""
        try:
            entries = s2n(self.file_handle, self.parent_offset, self.ifd_offset, 2, self.endian)
        except TypeError:
            logger.warning('Possibly corrupted IFD: %s', self.ifd_offset)
            return

        for i in range(entries):
            # entry is index of start of this IFD in the file
            entry = self.ifd_offset + 2 + 12 * i
            tag = s2n(self.file_handle, self.parent_offset, entry, 2, self.endian)

            # get tag name early to avoid errors, help debug
            tag_entry = self.tag_dict.get(tag)
            if tag_entry:
                tag_name = tag_entry[0]
            else:
                tag_name = 'Tag 0x%04X' % tag

            self._process_tag(self.ifd_offset, self.ifd_name, tag_entry, entry, tag, tag_name, DEFAULT_STOP_TAG, self.relative_tags)

            if tag_name == DEFAULT_STOP_TAG:
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
        truncate_tags: bool=True
    ):
        super().__init__(
            file_handle,
            ifd_name,
            parent_offset,
            ifd_offset,
            endian,
            fake_exif,
            IFD_TAG_MAP.get(ifd_name, {}),
            False,
            truncate_tags
        )

        self._sub_ifds: List[Optional[SubIfd]] = []
        self._dump_sub_ifds()

        # MakerNotes are not stored in sub_ifds because they're not an actual
        # SubIFD but a tag in the EXIF SubIFD whose value uses the EXIF
        # format.
        self.makernote: Union[MakerNote, None] = None
        try:
            self._dump_makernotes()
        except ValueError:
            logger.debug('MakerNote data not found.')

    def _dump_makernotes(self) -> None:
        """
        Decode all the camera-specific MakerNote formats
        """

        # Note is the data that comprises this MakerNote.
        # The MakerNote will likely have pointers in it that point to other
        # parts of the file. We'll use self.offset as the starting point for
        # most of those pointers, since they are relative to the beginning
        # of the file.
        #
        # If the MakerNote is in a newer format, it may use relative
        # addressing within the MakerNote. In that case we'll use relative
        # addresses for the pointers.
        #
        # As an aside: it's not just to be annoying that the manufacturers use
        # relative offsets.  It's so that if the makernote has to be moved by
        # the picture software all of the offsets don't have to be adjusted.
        # Overall this is probably the right strategy for makernotes, though
        # the spec is ambiguous.
        #
        # The spec does not appear to imagine that makernotes would follow
        # EXIF format internally.  Once they did, it's ambiguous whether the
        # offsets should be from the header at the start of all the EXIF info,
        # or from the header at the start of the makernote.
        #
        # TODO: look into splitting this up

        # MakerNote data is actually in the EXIF SubIFD.
        note = None
        for ifd in self.sub_ifds:
            if ifd.ifd_name == 'EXIF':
                note = ifd.tags['MakerNote']
                break

        if note is None:
            raise ValueError('No MakerNotes.')

        # Some apps use MakerNote tags but do not use a format for which we
        # have a description, so just do a raw dump for these.
        make = self.tags['Make'].printable

        # Nikon
        # The maker note usually starts with the word Nikon, followed by the
        # type of the makernote (1 or 2, as a short).  If the word Nikon is
        # not at the start of the makernote, it's probably type 2, since some
        # cameras work that way.
        if 'NIKON' in make:
            if note.values[0:7] == [78, 105, 107, 111, 110, 0, 1]:
                logger.debug('Looks like a type 1 Nikon MakerNote.')
                self.makernote = MakerNote(
                    self.file_handle,
                    'MakerNote',
                    self.parent_offset,
                    note.field_offset + 8,
                    self.endian,
                    self.fake_exif,
                    'NIKON',
                    makernote.nikon.TAGS_OLD,
                    False,
                    self.truncate_tags
                )

            elif note.values[0:7] == [78, 105, 107, 111, 110, 0, 2]:
                logger.debug('Looks like a labeled type 2 Nikon MakerNote')
                if note.values[12:14] != [0, 42] and note.values[12:14] != [42, 0]:
                    raise ValueError('Missing marker tag 42 in MakerNote.')
                    # skip the Makernote label and the TIFF header
                self.makernote = MakerNote(
                    self.file_handle,
                    'MakerNote',
                    0,
                    note.field_offset + 10 + 8,
                    self.endian,
                    self.fake_exif,
                    'NIKON',
                    makernote.nikon.TAGS_NEW,
                    True,
                    self.truncate_tags
                )
            else:
                # E99x or D1
                logger.debug('Looks like an unlabeled type 2 Nikon MakerNote')
                self.makernote = MakerNote(
                    self.file_handle,
                    'MakerNote',
                    self.parent_offset,
                    note.field_offset,
                    self.endian,
                    self.fake_exif,
                    'NIKON',
                    makernote.nikon.TAGS_NEW,
                    False,
                    self.truncate_tags
                )
            return

        # Olympus
        if make.startswith('OLYMPUS'):
            self.makernote = MakerNote(
                self.file_handle,
                'MakerNote',
                self.parent_offset,
                note.field_offset + 8,
                self.endian,
                self.fake_exif,
                'OLYMPUS',
                makernote.olympus.TAGS,
                False,
                self.truncate_tags
            )
            return

            # TODO
            #for i in (('MakerNote Tag 0x2020', makernote.OLYMPUS_TAG_0x2020),):
            #    self.decode_olympus_tag(self.tags[i[0]].values, i[1])
            #return

        # Casio
        if 'CASIO' in make or 'Casio' in make:
            self.makernote = MakerNote(
                self.file_handle,
                'MakerNote',
                self.parent_offset,
                note.field_offset,
                self.endian,
                self.fake_exif,
                'CASIO',
                makernote.casio.TAGS,
                False,
                self.truncate_tags
            )
            return

        # Fujifilm
        if make == 'FUJIFILM':
            # IFD offsets are from beginning of MakerNote, not beginning of
            # file header
            parent_offset = self.parent_offset + note.field_offset
            # everything else is "Motorola" endian, but the MakerNote is
            # "Intel" endian
            endian = 'I'
            self.makernote = MakerNote(
                self.file_handle,
                'MakerNote',
                parent_offset,
                12,
                endian,
                self.fake_exif,
                'FUJIFILM',
                makernote.fujifilm.TAGS,
                False,
                self.truncate_tags
            )
            return

        # Apple
        if make == 'Apple' and note.values[0:10] == [65, 112, 112, 108, 101, 32, 105, 79, 83, 0]:
            parent_offset = self.parent_offset + note.field_offset + 14

            self.makernote = MakerNote(
                self.file_handle,
                'MakerNote',
                parent_offset,
                0,
                self.endian,
                self.fake_exif,
                'APPLE',
                makernote.apple.TAGS,
                False,
                self.truncate_tags
            )
            return

        # Canon
        if make == 'Canon':
            self.makernote = MakerNote(
                self.file_handle,
                'MakerNote',
                self.parent_offset,
                note.field_offset,
                self.endian,
                self.fake_exif,
                'CANON',
                makernote.canon.TAGS,
                False,
                self.truncate_tags
            )

            # FIXME: Not sure what's going on here.
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

    def _dump_sub_ifds(self, ifd_offset: int=None, ifd_name: str=None, tag_dict: dict=None, stop_tag: str=DEFAULT_STOP_TAG) -> None:
        """Populate SubIFDs."""
        self.sub_ifds = []
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
        truncate_tags: bool=True
    ):
        super().__init__(
            file_handle,
            ifd_name,
            parent_offset,
            ifd_offset,
            endian,
            fake_exif,
            IFD_TAG_MAP.get(ifd_name, {}),
            False,
            truncate_tags
        )

        self.parent_ifd = parent_ifd


class MakerNote(IfdBase):
    """
    A MakerNote

    MakerNotes are not an actual SubIFD but a tag in the EXIF SubIFD whose
    value follows the EXIF format.
    """
    def __init__(
        self,
        file_handle: BinaryIO,
        ifd_name: str,
        parent_offset: int,
        ifd_offset: int,
        endian: str,
        fake_exif: int,
        maker_name: str,
        tag_dict: dict,
        relative_tags: bool=False,
        truncate_tags: bool=True
    ):
        super().__init__(
            file_handle,
            ifd_name,
            parent_offset,
            ifd_offset,
            endian,
            fake_exif,
            tag_dict,
            relative_tags,
            truncate_tags
        )

        self.relative_tags = relative_tags
        self.maker_name = maker_name
        self.tag_dict = tag_dict


class IfdTag:
    """
    Eases dealing with tags.
    """
    def __init__(
        self,
        tag: int,
        field_type: int,
        values: Any,
        field_offset: int,
        field_length: int,
        tag_entry: Any=None,
        truncate_tags: bool=True
    ):
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

        self.tag_entry = tag_entry
        self.truncate_tags = truncate_tags

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

    @property
    def printable(self):
        """
        Printable representation of tag.
        """
        # now 'values' is either a string or an array
        # TODO: use only one type
        if self.field_length == 1 and self.field_type != 2:
            printable = str(self.values[0])
        elif self.field_length > 50 and len(self.values) > 20 and not isinstance(self.values, str):
            if self.truncate_tags:
                printable = str(self.values[0:20])[0:-1] + ', ... ]'
            else:
                printable = str(self.values[0:-1])
        else:
            printable = str(self.values)

        # compute printable version of values
        if self.tag_entry:
            # optional 2nd tag element is present
            if len(self.tag_entry) != 1:
                if callable(self.tag_entry[1]):
                    # call mapping function
                    printable = self.tag_entry[1](self.values)

                elif isinstance(self.values, list):
                    # A list can be a list of the same type of value or a list of values with a
                    # different meaning by position.

                    pretty_values = []
                    if isinstance(self.tag_entry[1], list):
                        for _i in range(len(self.values)):
                            pretty_values.append(self.tag_entry[1][_i].get(self.values[_i], repr(self.values[_i])))
                    else:
                        for val in self.values:
                            pretty_values.append(self.tag_entry[1].get(val, repr(val)))

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
                    printable = self.tag_entry[1].get(val, repr(self.values))

        return printable


class IfdTagValue:
    """
    IFD Tag value
    """
    pass

