import struct
from typing import cast, Any, BinaryIO, Dict, List, Optional, Tuple, Union

from .exif_log import get_logger
from .utils import Ratio, s2n, FILE_TYPE_JPEG
from .tags import DEFAULT_STOP_TAG, FIELD_TYPES, SUBIFD_TAGS, IFD_TAG_MAP, makernote

logger = get_logger()

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
        tag_entry: Optional[Tuple[str, Any]]=None,
    ):
        self.field_type = field_type
        self.field_offset = field_offset
        self.field_length = field_length
        # FIXME: sort out this type mess!
        self.values = values

        self.tag_entry = tag_entry

        self.tag_id: str = '0x%04X' % (tag)
        self.tag_name: Union[str, None] = None
        if self.tag_entry is not None:
            self.tag_name = cast(Tuple, tag_entry)[0]

    def __str__(self) -> str:
        tag = '({}) {}={} @ {}'.format(
            self.tag_id,
            FIELD_TYPES[self.field_type][2],
            self.printable,
            self.field_offset
        )
        return tag

    def __repr__(self) -> str:
        tag = '<{}.{} tag_id={}, type={}, value={}, offset={} at {}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.tag_id,
            FIELD_TYPES[self.field_type][2],
            self.printable,
            self.field_offset,
            hex(id(self))
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


class IfdBase:
    """
    An Ifd
    """
    def __init__(
        self,
        file_handle: BinaryIO,
        file_type: str,
        ifd_name: str,
        parent_offset: int,
        ifd_offset: int,
        endian: str,
        tag_dict: dict,
        relative_tags: bool=False,
    ):
        self.file_type = file_type
        self.name = ifd_name
        self._parent_offset = parent_offset
        self.offset = ifd_offset
        self._endian = endian

        self._file_handle = file_handle
        self._tag_dict = tag_dict
        self._relative_tags = relative_tags

        self.tags = {}  # type: Dict[str, Any]

        self._dump_ifd()

    def __str__(self) -> str:
        return '{} @ {}'.format(self.name, self.offset)

    def __repr__(self) -> str:
        return '<{}.{} {} offset={}, endian={} at {}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.name,
            self.offset,
            self._endian,
            hex(id(self))
        )

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
                        s2n(self._file_handle, self._parent_offset, offset, 4, self._endian, signed),
                        s2n(self._file_handle, self._parent_offset, offset + 4, 4, self._endian, signed)
                    )
                elif field_type in (11, 12):
                    # a float or double
                    unpack_format = ''
                    if self._endian == 'I':
                        unpack_format += '<'
                    else:
                        unpack_format += '>'
                    if field_type == 11:
                        unpack_format += 'f'
                    else:
                        unpack_format += 'd'
                    self._file_handle.seek(self._parent_offset + offset)
                    byte_str = self._file_handle.read(type_length)
                    value = struct.unpack(unpack_format, byte_str)
                else:
                    value = s2n(self._file_handle, self._parent_offset, offset, type_length, self._endian, signed)
                values.append(value)
                offset = offset + type_length
        # The test above causes problems with tags that are
        # supposed to have long values! Fix up one important case.
        elif tag_name in ('MakerNote', makernote.canon.CAMERA_INFO_TAG_NAME):
            for _ in range(count):
                value = s2n(self._file_handle, self._parent_offset, offset, type_length, self._endian, signed)
                values.append(value)
                offset = offset + type_length
        return values

    def _process_field2(self, tag_name, count, offset):
        values = ''
        # special case: null-terminated ASCII string
        # XXX investigate
        # sometimes gets too big to fit in int value
        if count != 0:  # and count < (2**31):  # 2E31 is hardware dependent. --gd
            file_position = self._parent_offset + offset
            try:
                self._file_handle.seek(file_position)
                values = self._file_handle.read(count)

                # Drop any garbage after a null.
                values = values.split(b'\x00', 1)[0]
                if isinstance(values, bytes):
                    try:
                        values = values.decode('utf-8')
                    except UnicodeDecodeError:
                        logger.warning('Possibly corrupted field %s in %s IFD', tag_name, self.name)
            except OverflowError:
                logger.warning('OverflowError at position: %s, length: %s', file_position, count)
                values = ''
            except MemoryError:
                logger.warning('MemoryError at position: %s, length: %s', file_position, count)
                values = ''
        return values

    def _process_tag(self, tag_entry, entry, tag: int, tag_name, stop_tag) -> None:
        field_type = s2n(self._file_handle, self._parent_offset, entry + 2, 2, self._endian)

        # unknown field type
        if not 0 < field_type < len(FIELD_TYPES):
            return

        type_length = FIELD_TYPES[field_type][0]
        field_length = s2n(self._file_handle, self._parent_offset, entry + 4, 4, self._endian)
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
            if self._relative_tags:
                tmp_offset = s2n(self._file_handle, self._parent_offset, offset, 4, self._endian)
                offset = tmp_offset + self.offset - 8
                if self.file_type == FILE_TYPE_JPEG:
                    offset += 18
            else:
                offset = s2n(self._file_handle, self._parent_offset, offset, 4, self._endian)

        field_offset = offset
        values = None
        if field_type == 2:
            values = self._process_field2(tag_name, field_length, offset)
        else:
            values = self._process_field(tag_name, field_length, field_type, type_length, offset)

        self.tags[tag_name] = IfdTag(
            tag, field_type, values, field_offset, field_length * type_length, tag_entry
        )
        tag_value = repr(self.tags[tag_name])
        logger.debug(' %s: %s', tag_name, tag_value)

    def _dump_ifd(self) -> None:
        """Populate IFD tags."""
        try:
            entries = s2n(self._file_handle, self._parent_offset, self.offset, 2, self._endian)
        except TypeError:
            logger.warning('Possibly corrupted IFD: %s', self.offset)
            return

        for i in range(entries):
            # entry is index of start of this IFD in the file
            entry = self.offset + 2 + 12 * i
            tag = s2n(self._file_handle, self._parent_offset, entry, 2, self._endian)

            # get tag name early to avoid errors, help debug
            tag_entry = self._tag_dict.get(tag)
            if tag_entry:
                tag_name = tag_entry[0]
            else:
                tag_name = 'Tag 0x%04X' % tag

            self._process_tag(tag_entry, entry, tag, tag_name, DEFAULT_STOP_TAG)

            if tag_name == DEFAULT_STOP_TAG:
                break


class SubIfd(IfdBase):
    """
    A SubIfd
    """
    def __init__(
        self,
        file_handle: BinaryIO,
        file_type: str,
        ifd_name: str,
        parent_offset: int,
        ifd_offset: int,
        endian: str,
        parent_ifd: IfdBase,
    ):
        super().__init__(
            file_handle,
            file_type,
            ifd_name,
            parent_offset,
            ifd_offset,
            endian,
            IFD_TAG_MAP.get(ifd_name, {}),
            False,
        )

        self._parent_ifd = parent_ifd


class MakerNote(IfdBase):
    """
    A MakerNote

    MakerNotes are not an actual SubIFD but a tag in the EXIF SubIFD whose
    value follows the EXIF format.
    """
    def __init__(
        self,
        file_handle: BinaryIO,
        file_type: str,
        ifd_name: str,
        parent_offset: int,
        ifd_offset: int,
        endian: str,
        maker_name: str,
        tag_dict: dict,
        relative_tags: bool=False,
    ):
        super().__init__(
            file_handle,
            file_type,
            ifd_name,
            parent_offset,
            ifd_offset,
            endian,
            tag_dict,
            relative_tags,
        )

        self._tag_dict = tag_dict
        self.maker_name = maker_name


class Ifd(IfdBase):
    """
    An IFD
    """
    def __init__(
        self,
        file_handle: BinaryIO,
        file_type: str,
        ifd_name: str,
        parent_offset: int,
        ifd_offset: int,
        endian: str,
    ):
        super().__init__(
            file_handle,
            file_type,
            ifd_name,
            parent_offset,
            ifd_offset,
            endian,
            IFD_TAG_MAP.get('IFD', {}),
            False,
        )

        self._sub_ifds: List[SubIfd] = []
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
        for ifd in self._sub_ifds:
            if ifd.name == 'EXIF':
                note = ifd.tags.get('MakerNote')
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
                    self._file_handle,
                    self.file_type,
                    'MakerNote',
                    self._parent_offset,
                    note.field_offset + 8,
                    self._endian,
                    'NIKON',
                    makernote.nikon.TAGS_OLD,
                    False,
                )

            elif note.values[0:7] == [78, 105, 107, 111, 110, 0, 2]:
                logger.debug('Looks like a labeled type 2 Nikon MakerNote')
                if note.values[12:14] != [0, 42] and note.values[12:14] != [42, 0]:
                    raise ValueError('Missing marker tag 42 in MakerNote.')
                    # skip the Makernote label and the TIFF header
                self.makernote = MakerNote(
                    self._file_handle,
                    self.file_type,
                    'MakerNote',
                    0,
                    note.field_offset + 10 + 8,
                    self._endian,
                    'NIKON',
                    makernote.nikon.TAGS_NEW,
                    True,
                )
            else:
                # E99x or D1
                logger.debug('Looks like an unlabeled type 2 Nikon MakerNote')
                self.makernote = MakerNote(
                    self._file_handle,
                    self.file_type,
                    'MakerNote',
                    self._parent_offset,
                    note.field_offset,
                    self._endian,
                    'NIKON',
                    makernote.nikon.TAGS_NEW,
                    False,
                )

        # Olympus
        elif make.startswith('OLYMPUS'):
            self.makernote = MakerNote(
                self._file_handle,
                self.file_type,
                'MakerNote',
                self._parent_offset,
                note.field_offset + 8,
                self._endian,
                'OLYMPUS',
                makernote.olympus.TAGS,
                False,
            )

        # Casio
        elif 'CASIO' in make or 'Casio' in make:
            self.makernote = MakerNote(
                self._file_handle,
                self.file_type,
                'MakerNote',
                self._parent_offset,
                note.field_offset,
                self._endian,
                'CASIO',
                makernote.casio.TAGS,
                False,
            )

        # Fujifilm
        elif make == 'FUJIFILM':
            # IFD offsets are from beginning of MakerNote, not beginning of
            # file header
            parent_offset = self._parent_offset + note.field_offset
            # everything else is "Motorola" endian, but the MakerNote is
            # "Intel" endian
            endian = 'I'
            self.makernote = MakerNote(
                self._file_handle,
                self.file_type,
                'MakerNote',
                parent_offset,
                12,
                endian,
                'FUJIFILM',
                makernote.fujifilm.TAGS,
                False,
            )

        # Apple
        elif make == 'Apple' and note.values[0:10] == [65, 112, 112, 108, 101, 32, 105, 79, 83, 0]:
            parent_offset = self._parent_offset + note.field_offset + 14

            self.makernote = MakerNote(
                self._file_handle,
                self.file_type,
                'MakerNote',
                parent_offset,
                0,
                self._endian,
                'APPLE',
                makernote.apple.TAGS,
                False,
            )

        # Canon
        elif make == 'Canon':
            self.makernote = MakerNote(
                self._file_handle,
                self.file_type,
                'MakerNote',
                self._parent_offset,
                note.field_offset,
                self._endian,
                'CANON',
                makernote.canon.TAGS,
                False,
            )

        return

    def _dump_sub_ifds(self, ifd_offset: int=None, ifd_name: str=None, tag_dict: dict=None, stop_tag: str=DEFAULT_STOP_TAG) -> None:
        """Populate SubIFDs."""
        self._sub_ifds = []
        for t in SUBIFD_TAGS:
            tag_entry = SUBIFD_TAGS.get(t)
            tag = self.tags.get(t)
            if tag is not None and tag_entry is not None:
                try:
                    for value in tag.values:
                        logger.debug('%s SubIFD at offset %d:', tag_entry[0], value)
                        self._sub_ifds.append(
                            SubIfd(
                                self._file_handle,
                                self.file_type,
                                tag_entry[0],
                                self._parent_offset,
                                value,
                                self._endian,
                                self,
                            )
                        )
                except IndexError:
                    logger.warning('No values found for %s SubIFD', tag_entry[0])

    @property
    def exif_ifd(self) -> Union[SubIfd, None]:
        sub_ifd = None
        for _ifd in self._sub_ifds:
            if _ifd.name == 'EXIF':
                sub_ifd = _ifd
                break
        return sub_ifd

    @property
    def gps_ifd(self) -> Union[SubIfd, None]:
        sub_ifd = None
        for _ifd in self._sub_ifds:
            if _ifd.name == 'GPS':
                sub_ifd = _ifd
                break
        return sub_ifd

    @property
    def sub_ifds(self) -> List[SubIfd]:
        sub_ifds = []
        for _ifd in self._sub_ifds:
            if _ifd.name == 'SubIFD':
                sub_ifds.append(_ifd)
        return sub_ifds

    def get_tags(self) -> Dict[str, Union[IfdTag, Dict]]:
        """
        Get tags from IFD and SubIFDs
        """
        tags = self.tags

        sub_ifd_count = 0
        for _ifd in self.sub_ifds:
            ifd_name = _ifd.name + str(sub_ifd_count)
            tags[ifd_name] = _ifd.tags
            sub_ifd_count += 1

        if self.gps_ifd:
            tags[self.gps_ifd.name] = self.gps_ifd.tags

        if self.exif_ifd:
            tags[self.exif_ifd.name] = self.exif_ifd.tags

        if self.makernote:
            tags[self.makernote.name] = self.makernote.tags

        return tags

