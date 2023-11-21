from zelda.elf.parse import ElfHeader, ElfMagicIdent, ElfProgramHeader


def test_can_parse_magic_ident(elf_fixture_set):
    assert ElfMagicIdent.parse(elf_fixture_set.program) == elf_fixture_set.magic_ident


def test_can_parse_elf_header(elf_fixture_set):
    assert ElfHeader.parse(elf_fixture_set.program) == elf_fixture_set.elf_header


def test_can_parse_elf_program_header(elf_fixture_set):
    assert (
        ElfProgramHeader.parse_table(
            elf_fixture_set.elf_header, elf_fixture_set.program
        )
        == elf_fixture_set.program_header_table
    )


# TODO: Add tests for section headers
