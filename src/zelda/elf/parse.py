from typing import NamedTuple, Tuple
import enum
import struct

from zelda.types import Bytes


class ElfParseError(Exception):
    pass


class ElfClass(enum.IntEnum):
    NONE = 0
    ELF_32 = 1
    ELF_64 = 2

    def __repr__(self):
        return self.name


class ElfByteOrder(enum.IntEnum):
    INVALID = 0
    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2

    @property
    def struct_format(self):
        return "<" if self is self.LITTLE_ENDIAN else ">"

    def __repr__(self):
        return self.name


class ElfVersion(enum.IntEnum):
    INVALID = 0
    CURRENT = 1

    def __repr__(self):
        return self.name


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


class ElfFileType(enum.Flag):
    NONE = 0
    RELOCATABLE_OBJECT = 1
    EXECUTABLE = 2
    SHARED_OBJECT = 3
    CORE_DUMP = 4
    NUM = 5
    LOOS = 0xFE00
    HIOS = 0xFEFF
    LOPROC = 0xFF00
    HIPROC = 0xFFFF

    def __repr__(self):
        return self.name


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

    magic_ident: ElfMagicIdent
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
    section_header_string_table_index: int

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


class ElfSegmentType(enum.IntFlag):
    NULL = 0
    LOAD = 1
    DYNAMIC = 2
    INTERP = 3
    NOTE = 4
    RESERVED = 5
    PROGRAM_HEADER = 6
    TLS = 7
    NUM = 8
    LOOS = 0x60000000
    GNU_EH_FRAME = 0x6474E550
    GNU_STACK = 0x6474E551
    GNU_RELRO = 0x6474E552
    LOSUNW = 0x6FFFFFFA
    SUNWBSS = 0x6FFFFFFA
    SUNWSTACK = 0x6FFFFFFB
    HISUNW = 0x6FFFFFFF
    HIOS = 0x6FFFFFFF
    LOPROC = 0x70000000
    HIPROC = 0x7FFFFFFF

    def __repr__(self):
        return self.name if self.name is not None else "UNKNOWN"


class ElfSegmentFlags(enum.IntFlag):
    EXEC = 1
    WRITE = 1 << 1
    READ = 1 << 2
    MASKOS = 0x0FF00000
    MASKPROC = 0xF0000000

    def __repr__(self):
        return self.name if self.name is not None else "UNKNOWN"


class ElfProgramHeader(NamedTuple):
    """
    ELF-32 Format:
        4 bytes     Segment type
        4 bytes     Segment file offset
        4 bytes     Segment virtual address
        4 bytes     Segment physical address
        4 bytes     Segment size in file
        4 bytes     Segment size in memory
        4 bytes     Segment flags (NOTE: that flags are in a different spot for ELF-64)
        4 bytes     Segment alignment
    ELF-32 Total:
        32 bytes

    ELF-64 Format:
        4 bytes     Segment type
        4 bytes     Segment flags (NOTE: that flags are in a different spot for ELF-32)
        8 bytes     Segment file offset
        8 bytes     Segment virtual address
        8 bytes     Segment physical address
        8 bytes     Segment size in file
        8 bytes     Segment size in memory
        8 bytes     Segment alignment
    ELF-64 Total:
        56 bytes
    """

    segment_type: ElfSegmentType
    offset: int
    virtual_address: int
    physical_address: int
    file_size: int
    memory_size: int
    flags: ElfSegmentFlags
    alignment: int

    @classmethod
    def parse_table(
        cls, elf_header: ElfHeader, the_bytes: Bytes
    ) -> list["ElfProgramHeader"]:
        program_headers = []
        struct_bytes_format = cls._get_struct_format(elf_header.magic_ident)
        start = elf_header.program_header_offset
        step = elf_header.program_header_size
        stop = (step * elf_header.program_header_entry_count) + start
        flags_index = 6 if elf_header.magic_ident.elf_class is ElfClass.ELF_32 else 1
        elf64_offset = 0 if elf_header.magic_ident.elf_class is ElfClass.ELF_32 else 1
        for offset in range(start, stop, step):
            header = struct.unpack_from(struct_bytes_format, the_bytes, offset=offset)
            program_headers.append(
                cls(
                    ElfSegmentType(header[0]),
                    header[1 + elf64_offset],
                    header[2 + elf64_offset],
                    header[3 + elf64_offset],
                    header[4 + elf64_offset],
                    header[5 + elf64_offset],
                    ElfSegmentFlags(header[flags_index]),
                    header[7],
                )
            )
        return program_headers

    @staticmethod
    def _get_struct_format(magic_ident: ElfMagicIdent) -> str:
        if magic_ident.elf_class is ElfClass.ELF_32:
            return magic_ident.byte_order.struct_format + "IIIIIIII"
        else:  # ElfClass.ELF_64
            return magic_ident.byte_order.struct_format + "IIQQQQQQ"


class ElfSectionType(enum.Flag):
    NULL = 0
    PROGBITS = 1
    SYMTAB = 2
    STRTAB = 3
    RELA = 4
    HASH = 5
    DYNAMIC = 6
    NOTE = 7
    NOBITS = 8
    REL = 9
    SHLIB = 10
    DYNSYM = 11
    INIT_ARRAY = 14
    FINI_ARRAY = 15
    PREINIT_ARRAY = 16
    GROUP = 17
    SYMTAB_SHNDX = 18
    NUM = 19
    LOOS = 0x60000000
    GNU_ATTRIBUTES = 0x6FFFFFF5
    GNU_HASH = 0x6FFFFFF6
    GNU_LIBLIST = 0x6FFFFFF7
    CHECKSUM = 0x6FFFFFF8
    LOSUNW = 0x6FFFFFFA
    SUNW_move = 0x6FFFFFFA
    SUNW_COMDAT = 0x6FFFFFFB
    SUNW_syminfo = 0x6FFFFFFC
    GNU_verdef = 0x6FFFFFFD
    GNU_verneed = 0x6FFFFFFE
    GNU_versym = 0x6FFFFFFF
    HISUNW = 0x6FFFFFFF
    HIOS = 0x6FFFFFFF
    LOPROC = 0x70000000
    HIPROC = 0x7FFFFFFF
    LOUSER = 0x80000000
    HIUSER = 0x8FFFFFFF

    def __repr__(self):
        return self.name


class ElfSectionFlags(enum.Flag):
    NULL = 0
    WRITE = 1 << 0
    ALLOC = 1 << 1
    EXEC_INSTR = 1 << 2
    MERGE = 1 << 4
    STRINGS = 1 << 5
    INFO_LINK = 1 << 6
    LINK_ORDER = 1 << 7
    OS_NONCONFORMING = 1 << 8
    GROUP = 1 << 9
    TLS = 1 << 10
    COMPRESSED = 1 << 11
    MASKOS = 0x0FF00000
    MASKPROC = 0xF0000000
    ORDERED = 1 << 30
    EXCLUDE = 1 << 31

    def __repr__(self):
        return self.name


class ElfSectionHeader(NamedTuple):
    """
    Format:
        ELF-32      ELF-64
        ------      ------
        4 bytes	    4 bytes		Section name (string tbl index)
        4 bytes	    4 bytes		Section type
        4 bytes	    8 bytes		Section flags
        4 bytes	    8 bytes		Section virtual addr at execution
        4 bytes	    8 bytes		Section file offset
        4 bytes	    8 bytes		Section size in bytes
        4 bytes	    4 bytes		Link to another section
        4 bytes	    4 bytes		Additional section information
        4 bytes	    8 bytes		Section alignment
        4 bytes	    8 bytes		Entry size if section holds table
    Format:
        ELF-32      ELF-64
        ------      ------
        40 bytes    64 bytes
    """

    name_index: int
    section_type: ElfSectionType
    flags: ElfSectionFlags
    virtual_address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int

    @classmethod
    def parse_table(
        cls, elf_header: ElfHeader, the_bytes: Bytes
    ) -> list["ElfSectionHeader"]:
        section_headers = []
        struct_bytes_format = cls._get_struct_format(elf_header.magic_ident)
        start = elf_header.section_header_offset
        step = elf_header.section_header_size
        stop = (step * elf_header.section_header_entry_count) + start
        for offset in range(start, stop, step):
            name_index, section_type, flags, *rest = struct.unpack_from(
                struct_bytes_format, the_bytes, offset=offset
            )
            section_headers.append(
                cls(
                    name_index,
                    ElfSectionType(section_type),
                    ElfSectionFlags(flags),
                    *rest,
                )
            )
        return section_headers

    @staticmethod
    def _get_struct_format(magic_ident: ElfMagicIdent) -> str:
        if magic_ident.elf_class is ElfClass.ELF_32:
            return magic_ident.byte_order.struct_format + "IIIIIIIIII"
        else:  # ElfClass.ELF_64
            return magic_ident.byte_order.struct_format + "IIQQQQIIQQ"


class ElfStringTable:
    """
    name_index: int
    section_type: ElfSectionType
    flags: ElfSectionFlags
    virtual_address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int
    """

    __slots__ = (
        "string_table_header",
        "strings",
        "_index",
    )

    def __init__(self, string_table_header: ElfSectionHeader, file_contents: Bytes):
        self.string_table_header = string_table_header
        self.strings = file_contents[
            string_table_header.offset : string_table_header.offset
            + string_table_header.size
        ]
        self._index = 1

    def __getitem__(self, index: int) -> str:
        """Read null-terminated string"""
        ba = bytearray()
        for b in self.strings[index:]:
            if b == 0:
                break
            ba.append(b)
        return ba.decode("utf-8")

    def __iter__(self):
        return self

    def __next__(self):
        if self._index >= len(self.strings):
            raise StopIteration
        s = self[self._index]
        self._index += len(s) + 1
        return s


class ElfSpecialSectionIndices(enum.Enum):
    # fmt: off
    UNDEF = 0           # Undefined, missing, irrelevant, or meaningless
    LORESERVE = 0xFF00  # Lowest reserved index
    LOPROC = 0xFF00     # Lowest processor-specific index
    HIPROC = 0xFF1F     # Highest processor-specific index
    LOOS = 0xFF20       # Lowest operating system-specific index
    HIOS = 0xFF3F       # Highest operating system-specific index
    ABS = 0xFFF1        # Symbol has absolute value; does not need relocation
    COMMON = 0xFFF2     # FORTRAN COMMON or C external global variables
    XINDEX = 0xFFFF     # Mark that the index is >= SHN_LORESERVE
    HIRESERVE = 0xFFFF  # Highest reserved index
    # fmt: on


class ElfSymbolBinding(enum.Enum):
    LOCAL = 0
    GLOBAL = 1
    WEAK = 2


class ElfSymbolType(enum.Enum):
    NOTYPE = 0
    FUNC = 1
    OBJECT = 2
    SECTION = 3


class ElfSymbolVisibility(enum.Enum):
    DEFAULT = 0
    PROTECTED = 1
    HIDDEN = 2
    INTERNAL = 3


class ElfSymbol(NamedTuple):
    """
    ELF-32 Format:
        4 bytes	    Symbol name (string tbl index)
        4 bytes	    Symbol value
        4 bytes	    Symbol size
        1 byte      Symbol type and binding (4 bits type, 4 bits binding)
        1 byte	    Symbol visibility
        2 bytes     Section index
    ELF-32 Total:
        16 bytes

    ELF-64 Format:
        4 bytes     Symbol name (string tbl index)
        1 byte      Symbol type and binding
        1 byte      Symbol visibility
        2 bytes 	Section index
        8 bytes	    Symbol value
        8 bytes	    Symbol size
    ELF-64 Total:
        24 bytes

    """

    name_index: int
    value: int
    size: int
    type_: ElfSymbolType
    binding: ElfSymbolBinding
    visibility: ElfSymbolVisibility
    section_index: int

    @classmethod
    def parse_table(
        cls,
        elf_header: ElfHeader,
        symbol_table_header: ElfSectionHeader,
        the_bytes: Bytes,
    ) -> list["ElfSymbol"]:
        symbols = []
        start = symbol_table_header.offset
        step = symbol_table_header.entry_size
        stop = symbol_table_header.size + start
        parse_func = (
            cls._parse_elf_64
            if elf_header.magic_ident.elf_class is ElfClass.ELF_64
            else cls._parse_elf_32
        )
        for offset in range(start, stop, step):
            symbols.append(parse_func(elf_header.magic_ident, the_bytes, offset))
        return symbols

    @classmethod
    def _parse_elf_32(
        cls, magic_ident: ElfMagicIdent, the_bytes: Bytes, offset: int
    ) -> "ElfSymbol":
        struct_format = magic_ident.byte_order.struct_format + "IIIBBH"
        name_index, value, size, info, visibility, section_index = struct.unpack_from(
            struct_format, the_bytes, offset=offset
        )
        return cls(
            name_index,
            value,
            size,
            *ElfSymbol._parse_info(info),
            ElfSymbolVisibility(visibility),
            section_index,
        )

    @classmethod
    def _parse_elf_64(
        cls, magic_ident: ElfMagicIdent, the_bytes: Bytes, offset: int
    ) -> "ElfSymbol":
        struct_format = magic_ident.byte_order.struct_format + "IBBHQQ"
        name_index, info, visibility, section_index, value, size = struct.unpack_from(
            struct_format, the_bytes, offset=offset
        )
        return cls(
            name_index,
            value,
            size,
            *ElfSymbol._parse_info(info),
            ElfSymbolVisibility(visibility),
            section_index,
        )

    @staticmethod
    def _parse_info(info: int) -> Tuple[ElfSymbolType, ElfSymbolBinding]:
        """
        #define ELFN_ST_BIND(i)   ((i)>>4)
        #define ELFN_ST_TYPE(i)   ((i)&0xf)
        #define ELFN_ST_INFO(b,t) (((b)<<4)+((t)&0xf))
        """
        symbol_binding = info >> 4
        symbol_type = info & 0xF
        return ElfSymbolType(symbol_type), ElfSymbolBinding(symbol_binding)


class ElfFile:
    __slots__ = (
        "elf_header",
        "program_header_table",
        "section_header_table",
        "file_contents",
        "symbol_table",
        "string_table",
        "symbol_string_table",
        "size",
    )

    def __init__(
        self,
        elf_header: ElfHeader,
        program_header_table: list[ElfProgramHeader],
        section_header_table: list[ElfSectionHeader],
        symbol_table: list[ElfSymbol],
        file_contents: Bytes,
    ):
        self.elf_header = elf_header
        self.program_header_table = program_header_table
        self.section_header_table = section_header_table
        self.symbol_table = symbol_table
        self.string_table = ElfStringTable(
            section_header_table[elf_header.section_header_string_table_index],
            file_contents,
        )
        symbol_string_table_header = [
            t
            for t in section_header_table
            if t.section_type is ElfSectionType.STRTAB
            and self.string_table[t.name_index] == ".dynstr"
        ][0]
        self.symbol_string_table = ElfStringTable(
            symbol_string_table_header,
            file_contents,
        )
        self.file_contents = file_contents
        self.size = len(file_contents)

    @classmethod
    def parse(cls, file_contents: Bytes) -> "ElfFile":
        elf_header = ElfHeader.parse(file_contents)
        program_header_table = ElfProgramHeader.parse_table(elf_header, file_contents)
        section_header_table = ElfSectionHeader.parse_table(elf_header, file_contents)
        try:
            symbol_table_header = [
                t
                for t in section_header_table
                if t.section_type in (ElfSectionType.SYMTAB, ElfSectionType.DYNSYM)
            ][0]
        except IndexError:
            raise ElfParseError("Could not find symbol table!")
        symbol_table = ElfSymbol.parse_table(
            elf_header, symbol_table_header, file_contents
        )
        return cls(
            elf_header,
            program_header_table,
            section_header_table,
            symbol_table,
            file_contents,
        )

    def __repr__(self) -> str:
        return (
            f"<ElfFile"
            f" elf_header={self.elf_header}"
            f", program_headers={self.program_header_table}"
            f", section_headers={self.section_header_table}"
            f", size={self.size}"
            f">"
        )
