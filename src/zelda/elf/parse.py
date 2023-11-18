from typing import NamedTuple
import enum
import struct

from zelda.types import Bytes


class ElfParseError(Exception):
    pass


class ElfClass(enum.IntEnum):
    NONE = 0
    ELF_32 = 1
    ELF_64 = 2


class ElfByteOrder(enum.IntEnum):
    INVALID = 0
    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2

    @property
    def struct_format(self):
        return "<" if self is self.LITTLE_ENDIAN else ">"


class ElfVersion(enum.IntEnum):
    INVALID = 0
    CURRENT = 1


ELF_MAGIC = b"\x7fELF"
ELF_MAGIC_BYTES_STRUCT_FORMAT = "BBBBB7x"


class ElfMagicIdent(NamedTuple):
    """
    Format:
        4 bytes     magic
        1 byte      class
        1 byte      data (byte order)
        1 byte      version
        1 byte      OS/ABI
        1 byte      ABI version
        7 bytes     padding
    Total:
        16 bytes
    """

    magic: bytes
    elf_class: ElfClass
    byte_order: ElfByteOrder
    version: ElfVersion
    # Not using the rest of the info
    os_abi: int
    abi_version: int

    @classmethod
    def parse(cls, the_bytes: Bytes) -> "ElfMagicIdent":
        if the_bytes[:4] != ELF_MAGIC:
            raise ElfParseError("File is not ELF!")
        elf_class, byte_order, version, os_abi, abi_version = struct.unpack_from(
            ELF_MAGIC_BYTES_STRUCT_FORMAT, the_bytes, offset=4
        )
        return cls(
            ELF_MAGIC,
            ElfClass(elf_class),
            ElfByteOrder(byte_order),
            ElfVersion(version),
            os_abi,
            abi_version,
        )


class ElfFileType(enum.IntEnum):
    NONE = 0
    EXECUTABLE = 1
    SHARED_OBJECT = 2
    RELOCATABLE_OBJECT = 3
    CORE_DUMP = 4


class ElfHeader(NamedTuple):
    """
    Format:
        ELF-32      ELF-64
        ------      ------
        16 bytes    16 bytes        Magic number and other info
        2 bytes     2 bytes         Object file type
        2 bytes     2 bytes         Architecture
        4 bytes     4 bytes         Object file version
        4 bytes     8 bytes         Entry point virtual address
        4 bytes     8 bytes         Program header table file offset
        4 bytes     8 bytes         Section header table file offset
        4 bytes     4 bytes         Processor-specific flags
        2 bytes     2 bytes         ELF header size in bytes
        2 bytes     2 bytes         Program header table entry size
        2 bytes     2 bytes         Program header table entry count
        2 bytes     2 bytes         Section header table entry size
        2 bytes     2 bytes         Section header table entry count
        2 bytes     2 bytes         Section header string table index
    Total:
        ELF-32      ELF-64
        ------      ------
        52 bytes    64 bytes
    """

    magic_id: ElfMagicIdent
    file_type: ElfFileType
    arch: int  # The set of architectures is way too big for its own enum
    file_version: int
    entry_point_addr: int
    program_header_offset: int
    section_header_offset: int
    flags: int
    elf_header_size: int
    program_header_size: int
    program_header_entry_count: int
    section_header_size: int
    section_header_entry_count: int
    section_header_table_index: int

    @classmethod
    def parse(cls, the_bytes: Bytes) -> "ElfHeader":
        magic_ident = ElfMagicIdent.parse(the_bytes)
        struct_bytes_format = cls._get_struct_format(magic_ident)
        file_type, *rest = struct.unpack_from(struct_bytes_format, the_bytes, offset=16)
        return cls(magic_ident, ElfFileType(file_type), *rest)

    @staticmethod
    def _get_struct_format(magic_ident: ElfMagicIdent) -> str:
        if magic_ident.elf_class is ElfClass.ELF_32:
            return magic_ident.byte_order.struct_format + "HHIIIIIHHHHHH"
        else:  # ElfClass.ELF_64
            return magic_ident.byte_order.struct_format + "HHIQQQIHHHHHH"


def parse_elf(contents: Bytes) -> ElfHeader:
    return ElfHeader.parse(contents)


if __name__ == "__main__":
    import sys
    from pathlib import Path

    def main():
        if len(sys.argv) < 2:
            raise SystemExit("ERROR: Must include ELF file arg!")
        elf_file = Path(sys.argv[1])
        if not elf_file.exists():
            raise SystemExit(f"ERROR: Specified ELF file `{elf_file}` does not exist!")

        fbytes = elf_file.read_bytes()
        try:
            parsed = parse_elf(memoryview(fbytes))
        except ElfParseError as e:
            raise SystemExit(f"ERROR: {e.__class__.__name__} - {e}") from None
        print(f"Parsed contents of {elf_file}:")
        print(parsed)

    main()
