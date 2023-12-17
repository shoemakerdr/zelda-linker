import sys
from pathlib import Path

from zelda.elf.parse import ElfFile, ElfParseError


def arg_parser():
    pass


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
    print("ELF Header:")
    for field in parsed.elf_header._fields:
        print(f"    {field} => {repr(getattr(parsed.elf_header, field))}")
    print("Program Headers:")
    for h in parsed.program_header_table:
        print("   ", h)
        # print(
        #     f"    type={h.segment_type.name:16}\toffset={h.offset}\tflags={h.flags.name}"
        # )
    print("Section Headers:")
    for h in parsed.section_header_table:
        name = parsed.string_table[h.name_index]
        name = name if name else "[NULL]"
        print("   ", name)
        print("       ", h)
    print("Symbol Table")
    print(f"{'TYPE':<8}  {'BINDING':<8}  {'VIS':<8}  {'VALUE':<10}  {'NAME'}")
    print(f"{'=' * 8}  {'=' * 8}  {'=' * 8}  {'=' * 10}  {'=' * 24}")
    for s in parsed.symbol_table:
        name = parsed.symbol_string_table[s.name_index]
        print(
            f"{s.type_.name:<8}  {s.binding.name:<8}  {s.visibility.name:<8}  0x{s.value:<8x}  {name}"
        )


if __name__ == "__main__":
    main()
