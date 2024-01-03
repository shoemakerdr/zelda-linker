# ZeLDa - A Linker in pure Python

This project is a learning exercise to learn how linkers work. The goal of this is not speed or completeness of features.
It is purely as a learning exercise and tool. My hope is that this tool is written in such a way that it can be used
by others to learn how linkers work.


## TODO
* Parse ELF files
    * ~ELF Header~
    * ~Program Headers~
    * ~Section Headers~
    * Sections
        * `PROGBITS` - program data
        * `SYMTAB` - symbol table
        * ~`STRTAB` - string table~
        * `REL` - relocation
        * `RELA` - relocation with addends
        * `HASH` - symbol hash table
        * `DYNAMIC` - dynamic linking information
        * `NOTE` - note
        * `NOBITS` - uninitialized data (bss)
        * `DYNSYM` - dynamic linker symbol table
        * `INIT_ARRAY` - array of constructors
        * `FINI_ARRAY` - array of destructors
        * `PREINIT_ARRAY` - array of pre-constructors
        * Not sure if I'll do the rest... there are a lot
* Linking logic
    * TBD...


## Resources
### ELF Cheatsheet
[ELF Format Cheatsheet Github Gist](https://gist.github.com/shoemakerdr/7207c30e42af7aa0ab191f1bf72d78e5)

### Ian Lance Taylor's Blog
Ian Lance Taylor wrote the gold linker and has a famous blog series about linkers:
* [Part 1](https://www.airs.com/blog/archives/38)
* [Part 2](https://www.airs.com/blog/archives/39)
* [Part 3](https://www.airs.com/blog/archives/40)
* [Part 4](https://www.airs.com/blog/archives/41)
* [Part 5](https://www.airs.com/blog/archives/42)
* [Part 6](https://www.airs.com/blog/archives/43)
* [Part 7](https://www.airs.com/blog/archives/44)
* [Part 8](https://www.airs.com/blog/archives/45)
* [Part 9](https://www.airs.com/blog/archives/46)
* [Part 10](https://www.airs.com/blog/archives/47)
* [Part 11](https://www.airs.com/blog/archives/48)
* [Part 12](https://www.airs.com/blog/archives/49)
* [Part 13](https://www.airs.com/blog/archives/50)
* [Part 14](https://www.airs.com/blog/archives/51)
* [Part 15](https://www.airs.com/blog/archives/52)
* [Part 16](https://www.airs.com/blog/archives/53)
* [Part 17](https://www.airs.com/blog/archives/54)
* [Part 18](https://www.airs.com/blog/archives/55)
* [Part 19](https://www.airs.com/blog/archives/56)
* [Part 20](https://www.airs.com/blog/archives/57)


## Container Workflow
_Useful for running `readelf` and `objdump` on `elf_samples/` binaries_
```
# create image
$ docker image build -f dockerfiles/dev.Dockerfile -t zelda-dev .

# run container
$ docker run -ti zelda-dev /bin/bash
```
