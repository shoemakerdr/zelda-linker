import sys
from pathlib import Path

from zelda.elf.parse import ElfFile, ElfParseError, ElfSpecialSectionIndices


def arg_parser():
    pass


def display_header(elf_file: ElfFile) -> None:
    print("ELF Header:")
    for field in elf_file.elf_header._fields:
        print(f"    {field} => {repr(getattr(elf_file.elf_header, field))}")


def display_program_headers(elf_file: ElfFile) -> None:
    print("Program Headers:")
    for h in elf_file.program_header_table:
        print("   ", h)


def display_section_headers(elf_file: ElfFile) -> None:
    print("Section Headers:")
    for name, h in elf_file.section_header_table:
        name = name if name else "[NULL]"
        print("   ", name)
        print("       ", h)


def display_symbol_tables(elf_file: ElfFile) -> None:
    indent = " " * 4
    if not elf_file.symbol_tables:
        return
    print("Symbol Tables:")
    for table in elf_file.symbol_tables:
        print()
        print(table.header.section_type)
        print()
        print(
            f"{indent}{'TYPE':<8}  {'BINDING':<8}  {'VIS':<8}  {'SECTION':<10}  {'VALUE':<10}  {'NAME'}"
        )
        print(
            f"{indent}{'=' * 8}  {'=' * 8}  {'=' * 8}  {'=' * 10}  {'=' * 10}  {'=' * 24}"
        )
        for name, s in table:
            value = None
            if s.section_index in ElfSpecialSectionIndices:
                section_name = ElfSpecialSectionIndices(s.section_index).name
                if (
                    ElfSpecialSectionIndices(s.section_index)
                    is ElfSpecialSectionIndices.UNDEF
                ):
                    value = " " * 10
            else:
                section_name = elf_file.section_header_table[s.section_index][0]
            value = f"0x{s.value:<8x}" if value is None else value
            print(
                f"{indent}{s.type_.name:<8}  {s.binding.name:<8}  {s.visibility.name:<8}  {section_name:<10}  {value}  {name}"
            )


def main():
    if len(sys.argv) < 2:
        raise SystemExit("ERROR: Must include ELF file arg!")
    elf_file = Path(sys.argv[1])
    if not elf_file.exists():
        raise SystemExit(f"ERROR: Specified ELF file `{elf_file}` does not exist!")

    fbytes = elf_file.read_bytes()
    try:
        parsed = ElfFile.parse(memoryview(fbytes))
    except ElfParseError as e:
        raise SystemExit(f"ERROR: {e.__class__.__name__} - {e}") from None
    print(f"Parsed contents of {elf_file}")
    print(f"==================={len(str(elf_file)) * '='}")
    display_header(parsed)
    # display_program_headers(parsed)
    display_section_headers(parsed)
    display_symbol_tables(parsed)


if __name__ == "__main__":
    main()
