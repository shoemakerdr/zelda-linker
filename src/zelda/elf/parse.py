from typing import Any, NamedTuple
import enum
import struct


class ElfParseError(Exception):
    pass


class ElfClass(enum.IntEnum):
    NONE = 0
    ELF_32 = 1
    ELF_64 = 2


class ElfData(enum.IntEnum):
    INVALID = 0
    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2

    @property
    def struct_format(self):
        return "<" if self is self.LITTLE_ENDIAN else ">"


class ElfVersion(enum.IntEnum):
    INVALID = 0
    CURRENT = 1


ELF_MAGIC = bytearray([0x7F, 0x45, 0x4C, 0x46])  # 0x7fELF
ELF_MAGIC_BYTES_FORMAT = "BBBBB7x"


class ElfMagicIdent(NamedTuple):
    """
    Format:
        4 bytes     magic
        1 byte      class
        1 byte      data
        1 byte      version
        1 byte      OS/ABI
        1 byte      ABI version
        7 bytes     padding
    """

    elf_class: ElfClass
    data: ElfData
    version: ElfVersion
    # Not using the rest of the info
    os_abi: int
    abi_version: int

    @classmethod
    def parse(cls, the_bytes):
        if the_bytes[:4] != ELF_MAGIC:
            raise ElfParseError("File is not ELF!")
        elf_class, data, version, os_abi, abi_version = struct.unpack_from(
            ELF_MAGIC_BYTES_FORMAT, the_bytes, offset=4
        )
        return cls(
            ElfClass(elf_class), ElfData(data), ElfVersion(version), os_abi, abi_version
        )


class ElfFileType(enum.IntEnum):
    NONE = 0
    EXECUTABLE = 1
    SHARED_OBJECT = 2
    RELOCATABLE_OBJECT = 3
    CORE_DUMP = 4


ELF_STRUCT_BYTES_FORMATS = {
    ElfClass.ELF_32: "HHIIIIIHHHHHH",
    ElfClass.ELF_64: "HHIQQQIHHHHHH",
}


def get_struct_bytes_format(magic_ident: ElfMagicIdent) -> str:
    return (
        magic_ident.data.struct_format + ELF_STRUCT_BYTES_FORMATS[magic_ident.elf_class]
    )


class ElfHeader(NamedTuple):
    """
    typedef struct
    {
      unsigned char	e_ident[16];	    /* Magic number and other info */
      uint16_t      e_type;		    	/* Object file type */
      uint16_t      e_machine;	    	/* Architecture */
      uint32_t      e_version;	    	/* Object file version */
      uint32_t      e_entry;	    	/* Entry point virtual address */
      uint32_t      e_phoff;	    	/* Program header table file offset */
      uint32_t      e_shoff;	    	/* Section header table file offset */
      uint32_t      e_flags;	    	/* Processor-specific flags */
      uint16_t      e_ehsize;	    	/* ELF header size in bytes */
      uint16_t      e_phentsize;		/* Program header table entry size */
      uint16_t      e_phnum;	    	/* Program header table entry count */
      uint16_t      e_shentsize;		/* Section header table entry size */
      uint16_t      e_shnum;	    	/* Section header table entry count */
      uint16_t      e_shstrndx;	    	/* Section header string table index */
    } Elf32_Ehdr;

    typedef struct
    {
      unsigned char	e_ident[16];	    /* Magic number and other info */
      uint16_t      e_type;		    	/* Object file type */
      uint16_t      e_machine;	    	/* Architecture */
      uint32_t      e_version;	    	/* Object file version */
      uint64_t      e_entry;	    	/* Entry point virtual address */
      uint64_t      e_phoff;	    	/* Program header table file offset */
      uint64_t      e_shoff;	    	/* Section header table file offset */
      uint32_t      e_flags;	    	/* Processor-specific flags */
      uint16_t      e_ehsize;	    	/* ELF header size in bytes */
      uint16_t      e_phentsize;		/* Program header table entry size */
      uint16_t      e_phnum;	    	/* Program header table entry count */
      uint16_t      e_shentsize;		/* Section header table entry size */
      uint16_t      e_shnum;	    	/* Section header table entry count */
      uint16_t      e_shstrndx;	    	/* Section header string table index */
    } Elf64_Ehdr;
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
    def parse(cls, the_bytes: bytes) -> "ElfHeader":
        magic_ident = ElfMagicIdent.parse(the_bytes)
        struct_bytes_format = get_struct_bytes_format(magic_ident)
        file_type, *rest = struct.unpack_from(struct_bytes_format, the_bytes, offset=16)
        return cls(magic_ident, ElfFileType(file_type), *rest)


def parse_elf(contents: bytes) -> dict[str, Any]:
    print(contents)
    return {}


if __name__ == "__main__":
    import sys
    from pathlib import Path

    def main():
        if len(sys.argv) < 2:
            raise SystemExit("ERROR: Must include ELF file arg!")
        elf_file = Path(sys.argv[1])
        if not elf_file.exists():
            raise SystemExit(f"ERROR: Specified ELF file `{elf_file}` does not exist!")

        print(f"Contents of {elf_file}:")
        fbytes = elf_file.read_bytes()
        parsed = parse_elf(memoryview(fbytes))
        print(parsed)

    main()
