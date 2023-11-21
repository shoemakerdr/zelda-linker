from zelda.elf.parse import ElfHeader, ElfMagicIdent, ElfProgramHeader, ElfSectionHeader


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


def test_can_parse_elf_section_header(elf_fixture_set):
    assert ElfSectionHeader.parse_table(
        elf_fixture_set.elf_header, elf_fixture_set.program
    ) == list(elf_fixture_set.section_header_table.values())


def test_can_parse_elf_string_table(elf_fixture_set):
    for name, header in elf_fixture_set.section_header_table.items():
        assert elf_fixture_set.string_table[header.name_index] == name
