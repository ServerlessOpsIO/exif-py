'''
File image
'''
from typing import BinaryIO, Optional

from .ifd import IfdBase

IMAGE_UNKNOWN_COMPRESSION = 'UNKNOWN'
IMAGE_UNKNOWN_FILE_TYPE = 'UNKNOWN'

class Image:
    '''
    File image
    '''
    def __init__(self,
                 file_type: str,
                 compression: str,
                 image_bytes: BinaryIO,
                 ifd: IfdBase
        ):
        self.file_type = file_type
        self.compression = compression
        self.image_bytes = image_bytes
        self.ifd = ifd

    def __str__(self) -> str:
        return '{} ({}) Image'.format(self.compression, self.file_type)

    def __repr__(self) -> str:
        return '<{}.{} {} compression={} at {}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.file_type,
            self.compression,
            hex(id(self))
        )

