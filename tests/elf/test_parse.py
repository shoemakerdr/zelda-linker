from zelda.elf.parse import ElfHeader, ElfMagicIdent


def test_can_parse_magic_ident_little_endian(elf_fixture_set):
    assert ElfMagicIdent.parse(elf_fixture_set.program) == elf_fixture_set.magic_ident


def test_can_parse_elf_header_little_endian(elf_fixture_set):
    assert ElfHeader.parse(elf_fixture_set.program) == elf_fixture_set.elf_header
