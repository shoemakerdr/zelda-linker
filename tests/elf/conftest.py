from typing import NamedTuple, Union
import pytest

from zelda.elf.parse import (
    ELF_MAGIC,
    ElfClass,
    ElfData,
    ElfFileType,
    ElfHeader,
    ElfMagicIdent,
    ElfVersion,
)


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
        ELF_MAGIC, ElfClass.ELF_64, ElfData.LITTLE_ENDIAN, ElfVersion.CURRENT, 0, 0
    )


@pytest.fixture
def little_endian_elf_header(little_endian_magic_ident, elf_header_tuple):
    return ElfHeader(little_endian_magic_ident, *elf_header_tuple)


@pytest.fixture
def little_endian_elf_program():
    # fmt: off
    # ELF Header
    return bytearray([
        0x7F, 0x45, 0x4C, 0x46,  # magic number
        0x02,  # ELF-64
        0x01,  # little endian
        0x01,  # ELF version
        0x00,  # System V ABI
        0x00,  # ABI version
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # unused bytes
        0x02, 0x00,  # executable object file
        0x3E, 0x00,  # x86-64 (AMD 64)
        0x01, 0x00, 0x00, 0x00,  # ELF version
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  # entry point
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # program header offset
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # section header table offset
        0x00, 0x00, 0x00, 0x00,  # flags
        0x40, 0x00,  # ELF header size
        0x38, 0x00,  # program header entry size
        0x01, 0x00,  # program header entry count
        0x00, 0x00,  # section header table entry size
        0x00, 0x00,  # section header table entry count
        0x00, 0x00,  # string table index

        # Program Header (.text = 0x400000 compared to 0x8048000 on x86)
        0x01, 0x00, 0x00, 0x00,  # loadable program
        0x05, 0x00, 0x00, 0x00,  # permissions (read & execute flags)
        0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # program offset (ELF header size + this program header size)
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  # program virtual address (0x400000 + offset)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # physical address (irrelevant for x86-64)
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # file size (just count the bytes for your machine instructions)
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # memory size (if this is greater than file size, then it zeros out the extra memory)
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # alignment

        # Program
        # Entry = 0x400078
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  # mov rax, 60
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,  # mov rdi, 42
        0x0F, 0x05,  # syscall (the newer syscall instruction for x86-64 int 0x80 on x86)
    ])
    # fmt: on


@pytest.fixture
def big_endian_magic_ident():
    return ElfMagicIdent(
        ELF_MAGIC, ElfClass.ELF_64, ElfData.BIG_ENDIAN, ElfVersion.CURRENT, 0, 0
    )


@pytest.fixture
def big_endian_elf_header(big_endian_magic_ident, elf_header_tuple):
    return ElfHeader(big_endian_magic_ident, *elf_header_tuple)


@pytest.fixture
def big_endian_elf_program():
    # fmt: off
    # ELF Header
    return bytearray([
        0x7F, 0x45, 0x4C, 0x46,  # magic number
        0x02,  # ELF-64
        0x02,  # big endian
        0x01,  # ELF version
        0x00,  # System V ABI
        0x00,  # ABI version
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # unused bytes
        0x00, 0x02,  # executable object file
        0x00, 0x3E,  # x86-64 (AMD 64)
        0x00, 0x00, 0x00, 0x01,  # ELF version
        0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x78,  # entry point
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,  # program header offset
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # section header table offset
        0x00, 0x00, 0x00, 0x00,  # flags
        0x00, 0x40,  # ELF header size
        0x00, 0x38,  # program header entry size
        0x00, 0x01,  # program header entry count
        0x00, 0x00,  # section header table entry size
        0x00, 0x00,  # section header table entry count
        0x00, 0x00,  # string table index

        # Program Header (.text = 0x400000 compared to 0x8048000 on x86)
        0x00, 0x00, 0x00, 0x01,  # loadable program
        0x00, 0x00, 0x00, 0x05,  # permissions (read & execute flags)

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78,  # program offset (ELF header size + this program header size)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x78,  # program virtual address (0x400000 + offset)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # physical address (irrelevant for x86-64)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,  # file size (just count the bytes for your machine instructions)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,  # memory size (if this is greater than file size, then it zeros out the extra memory)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,  # alignment

        # Program
        # Entry = 0x400078
        0xC7, 0x48, 0xC0, 0x00, 0x00, 0x00, 0x3C,  # mov rax, 60
        0xC7, 0x48, 0xC7, 0x00, 0x00, 0x00, 0x2A,  # mov rdi, 42
        0x05, 0x0F,  # syscall (the newer syscall instruction for x86-64 int 0x80 on x86)
    ])
    # fmt: on


class ElfFixtureSet(NamedTuple):
    magic_ident: ElfMagicIdent
    elf_header: ElfHeader
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
):
    if request.param == "little":
        return ElfFixtureSet(
            little_endian_magic_ident,
            little_endian_elf_header,
            little_endian_elf_program,
        )

    else:
        return ElfFixtureSet(
            big_endian_magic_ident,
            big_endian_elf_header,
            big_endian_elf_program,
        )
