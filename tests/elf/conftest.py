from typing import NamedTuple, Union
import pytest

from zelda.elf.parse import (
    ELF_MAGIC,
    ElfClass,
    ElfByteOrder,
    ElfFileType,
    ElfHeader,
    ElfMagicIdent,
    ElfPermissionFlags,
    ElfProgramHeader,
    ElfSegmentType,
    ElfVersion,
)


def little_endian_byte_orderer(order_to: str, byte_list: list[int]):
    if order_to == "big":
        byte_list.reverse()
    return byte_list


@pytest.fixture
def elf_program_maker():
    def maker(byte_order: str):
        # fmt: off
        return bytearray([
            # ELF Header
            0x7F, 0x45, 0x4C, 0x46,  # magic number
            0x02,  # ELF-64
            (0x01 if byte_order == "little" else 0x02),  # byte order
            0x01,  # ELF version
            0x00,  # System V ABI
            0x00,  # ABI version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # unused bytes
            *little_endian_byte_orderer(byte_order, [0x02, 0x00,]),  # executable object file
            *little_endian_byte_orderer(byte_order, [0x3E, 0x00,]),  # x86-64 (AMD 64)
            *little_endian_byte_orderer(byte_order, [0x01, 0x00, 0x00, 0x00,]),  # ELF version
            *little_endian_byte_orderer(byte_order, [0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,]),  # entry point
            *little_endian_byte_orderer(byte_order, [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,]),  # program header offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # section header table offset
            0x00, 0x00, 0x00, 0x00,  # flags
            *little_endian_byte_orderer(byte_order, [0x40, 0x00,]),  # ELF header size
            *little_endian_byte_orderer(byte_order, [0x38, 0x00,]),  # program header entry size
            *little_endian_byte_orderer(byte_order, [0x01, 0x00,]),  # program header entry count
            0x00, 0x00,  # section header table entry size
            0x00, 0x00,  # section header table entry count
            0x00, 0x00,  # string table index

            # Program Header (.text = 0x400000 compared to 0x8048000 on x86),
            *little_endian_byte_orderer(byte_order, [0x01, 0x00, 0x00, 0x00,]),  # loadable program
            *little_endian_byte_orderer(byte_order, [0x05, 0x00, 0x00, 0x00,]),  # permissions (read & execute flags)
            *little_endian_byte_orderer(byte_order, [0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,]),  # program offset (ELF header size + this program header size)
            *little_endian_byte_orderer(byte_order, [0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,]),  # program virtual address (0x400000 + offset)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # physical address (irrelevant for x86-64)
            *little_endian_byte_orderer(byte_order, [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,]),  # file size (just count the bytes for your machine instructions)
            *little_endian_byte_orderer(byte_order, [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,]),  # memory size (if this is greater than file size, then it zeros out the extra memory)
            *little_endian_byte_orderer(byte_order, [0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,]),  # alignment

            # Program
            # Entry = 0x400078
            *little_endian_byte_orderer(byte_order, [0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,]),  # mov rax, 60
            *little_endian_byte_orderer(byte_order, [0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,]),  # mov rdi, 42
            *little_endian_byte_orderer(byte_order, [0x0F, 0x05,]),  # syscall (the newer syscall instruction for x86-64 int 0x80 on x86)
        ])
        # fmt: on

    return maker


@pytest.fixture
def elf_header_tuple():
    return (
        ElfFileType(2),
        0x3E,
        1,
        0x0400078,
        0x40,
        0,
        0,
        0x40,
        0x38,
        1,
        0,
        0,
        0,
    )


@pytest.fixture
def little_endian_magic_ident():
    return ElfMagicIdent(
        ELF_MAGIC, ElfClass.ELF_64, ElfByteOrder.LITTLE_ENDIAN, ElfVersion.CURRENT, 0, 0
    )


@pytest.fixture
def little_endian_elf_header(little_endian_magic_ident, elf_header_tuple):
    return ElfHeader(little_endian_magic_ident, *elf_header_tuple)


@pytest.fixture
def little_endian_elf_program(elf_program_maker):
    return elf_program_maker("little")


@pytest.fixture
def big_endian_magic_ident():
    return ElfMagicIdent(
        ELF_MAGIC, ElfClass.ELF_64, ElfByteOrder.BIG_ENDIAN, ElfVersion.CURRENT, 0, 0
    )


@pytest.fixture
def big_endian_elf_header(big_endian_magic_ident, elf_header_tuple):
    return ElfHeader(big_endian_magic_ident, *elf_header_tuple)


@pytest.fixture
def big_endian_elf_program(elf_program_maker):
    return elf_program_maker("big")


@pytest.fixture
def elf_program_header_table():
    return [
        ElfProgramHeader(
            ElfSegmentType.LOAD, 0x78, 0x400078, 0, 16, 16, ElfPermissionFlags(5), 4096
        )
    ]


class ElfFixtureSet(NamedTuple):
    magic_ident: ElfMagicIdent
    elf_header: ElfHeader
    program_header_table: list[ElfProgramHeader]
    program: Union[bytes, bytearray, memoryview]


@pytest.fixture(params=["big", "little"])
def elf_fixture_set(
    request,
    little_endian_magic_ident,
    little_endian_elf_header,
    little_endian_elf_program,
    big_endian_magic_ident,
    big_endian_elf_header,
    big_endian_elf_program,
    elf_program_header_table,
):
    if request.param == "little":
        return ElfFixtureSet(
            little_endian_magic_ident,
            little_endian_elf_header,
            elf_program_header_table,
            little_endian_elf_program,
        )

    else:
        return ElfFixtureSet(
            big_endian_magic_ident,
            big_endian_elf_header,
            elf_program_header_table,
            big_endian_elf_program,
        )
