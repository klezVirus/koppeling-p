import struct
import sys
import argparse
from pathlib import Path
from typing import List, Union

import lief
import pefile
import copy

DEFAULT_CHARACTERISTICS = 0x40000040
SECTION_NAME = 8


class Function:
    def __init__(self, name, ordinal, address, forwarded: bool = False):
        self.__function_name = name.encode() + b"\x00"
        self.__function_ordinal = ordinal
        self.__function_address = address
        self.__forwarded = forwarded

    @property
    def library(self) -> bytes:
        if self.name.find(b".") == -1:
            return b""
        return self.name.split(b".")[0] + b"."

    @property
    def name(self) -> bytes:
        return self.__function_name

    @property
    def short_name(self) -> bytes:
        return self.name.replace(self.library, b"")

    @property
    def ordinal(self) -> int:
        return self.__function_ordinal

    @property
    def address(self) -> int:
        return self.__function_address

    @address.setter
    def address(self, address):
        self.__function_address = address

    @property
    def is_forwarded(self):
        return self.__forwarded


class ExportDataDirectory:
    def __init__(self, dll_name: Path, base_address: int = 0, spoof_name: Union[Path, None] = None):
        self.base = 0
        self.base_address = base_address
        self.dll_name = dll_name.name.encode() + b"\x00"
        self.library = str(dll_name).replace(dll_name.suffix, "")
        if spoof_name is not None:
            self.dll_name = spoof_name.name.encode() + b"\x00"
        self.__characteristics = DEFAULT_CHARACTERISTICS
        self.__timestamp = 0x0
        self.__major_version = 0x0
        self.__minor_version = 0x0
        self.__name = 0x0
        self.__entries: List[Function] = []
        self.__end_of_export_dir = 0x28
        self.__name = 0x0

    @property
    def characteristics(self):
        return self.__characteristics

    @characteristics.setter
    def characteristics(self, characteristics: int):
        self.__characteristics = characteristics

    def reset_base_address(self, value: int):
        for i in range(len(self.__entries)):
            if self.__entries[i].is_forwarded:
                self.__entries[i].address -= self.base_address
                self.__entries[i].address += value
        self.base_address = value

    def set_timestamp(self, timestamp: int) -> None:
        self.__timestamp = timestamp

    @property
    def number_of_functions(self):
        return len(self.__entries)

    @property
    def number_of_names(self):
        return len(self.__entries)

    @property
    def name_rva(self):
        return (
                self.base_address +
                self.__end_of_export_dir +
                (4 * len(self.__entries)) +  # Addresses of function
                (4 * len(self.__entries)) +  # Addresses of Names
                (2 * len(self.__entries))  # List of Ordinals
        )

    @property
    def real_function_names_rva(self):
        return self.name_rva + len(self.dll_name)

    @property
    def function_names_rva(self):
        return self.function_address_rva + (4 * len(self.__entries))

    @property
    def function_address_rva(self):
        return self.base_address + self.__end_of_export_dir

    @property
    def function_ordinal_rva(self):
        # End of "ED Headers" + Function RV Addresses
        return self.function_address_rva + (4 * len(self.__entries)) * 2

    def __add_function(self, name: str, address: int, forwarded=False):
        ordinal = len(self.__entries) + self.base
        self.__entries.append(
            Function(
                name=name,
                ordinal=ordinal,
                address=address,
                forwarded=forwarded
            )
        )

    def add_function(self, name: str, address: int):
        self.__add_function(name, address, forwarded=False)

    def add_forwarded_function(self, name: str):
        address = self.base_address + len(self.compile())
        name = f"{self.library}.{name}"
        self.__add_function(name, address, forwarded=True)

    def compile(self) -> bytes:
        name_rva = self.real_function_names_rva
        all_names_rvas = []

        # Locate first function name. If the name is an export, we will need to "advance" the start of
        # AddressOfNames till the function name (without the DLL path)
        # After that, we will proceed analysing exports, if a non-exported function is found, we will need
        # to:
        # 1. If the previous function is not forwarded and the current is, we advance the pointer of the DLL name
        # 2. If the previous function is forwarded and the current is, we advance the pointer of the full function name
        # 3. If the previous and current functions are not forwarded , we advance the pointer of the short function name

        for i in range(self.number_of_names):
            # print(f"{self.__entries[i].name} : {hex(name_rva)}")
            if self.__entries[i].is_forwarded:
                name_rva += len(self.__entries[i].library)
            all_names_rvas.append(name_rva)
            name_rva += len(self.__entries[i].short_name)

        # Now, to fix the addresses (which needs to point to the start of the full function names)
        # We go through all the entries and fix the pointers by addressing the deltas
        functions = [e for e in self.__entries]
        for i in range(self.number_of_names):
            if functions[i].is_forwarded:
                functions[i].address = all_names_rvas[i] - len(functions[i].library)

        # First, the directory
        return (
                struct.pack("<I", self.__characteristics) +
                struct.pack("<I", self.__timestamp) +
                struct.pack("<H", self.__major_version) +
                struct.pack("<H", self.__minor_version) +
                struct.pack("<I", self.name_rva) +
                struct.pack("<I", self.base) +
                struct.pack("<I", self.number_of_functions) +
                struct.pack("<I", self.number_of_names) +
                struct.pack("<I", self.function_address_rva) +
                struct.pack("<I", self.function_names_rva) +
                struct.pack("<I", self.function_ordinal_rva) +

                b"".join(
                    struct.pack("<I", x.address) for x in functions
                ) +
                b"".join(
                    struct.pack("<I", x) for x in all_names_rvas
                )
                + b"".join(
            struct.pack("<H", x.ordinal) for x in self.__entries
        ) + self.dll_name

                + b"".join(
            x.name for x in self.__entries
        )
        )


class KoppelingNG:

    def __init__(self):
        self.debug = False  # Config().get_boolean("DEBUG", "utilities")

    def align_up(self, value, align=0x1000):
        return (value + align - 1) & ~(align - 1)

    def add_section(self, pe, name, size, characteristics=DEFAULT_CHARACTERISTICS):
        # Sanity checks
        if len(name) > SECTION_NAME:
            raise Exception('[!] Section name is too long')

        section_header_size = pefile.Structure(pefile.PE.__IMAGE_SECTION_HEADER_format__).sizeof()
        section_header_off = pe.sections[-1].get_file_offset() + section_header_size
        if section_header_off + section_header_size > pe.OPTIONAL_HEADER.SizeOfHeaders:
            raise Exception('[!] Not enough room for another SECTION_HEADER')

        # Calculate/Align sizes
        virtual_size = self.align_up(size, pe.OPTIONAL_HEADER.SectionAlignment)
        virtual_addr = self.align_up(
            pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize,
            pe.OPTIONAL_HEADER.SectionAlignment
        )

        raw_size = self.align_up(size, pe.OPTIONAL_HEADER.FileAlignment)
        raw_ptr = self.align_up(
            pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData,
            pe.OPTIONAL_HEADER.FileAlignment
        )

        # Configure section properties
        section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
        section.set_file_offset(section_header_off)
        section.Name = name.encode().ljust(SECTION_NAME, b'\x00')
        section.VirtualAddress = virtual_addr
        section.PointerToRawData = raw_ptr
        section.Misc = section.Misc_VirtualSize = virtual_size
        section.SizeOfRawData = raw_size
        section.Characteristics = characteristics

        section.PointerToRelocations = 0
        section.NumberOfRelocations = 0
        section.NumberOfLinenumbers = 0
        section.PointerToLinenumbers = 0

        # Correct headers
        pe.FILE_HEADER.NumberOfSections += 1
        pe.OPTIONAL_HEADER.SizeOfImage = virtual_addr + virtual_size

        # Add buffer padding
        pe.__data__ += b'\x00' * raw_size

        # Append to ensure overwrite
        pe.__structures__.append(section)

        # Recreate to save our changes
        pe = pefile.PE(data=pe.write())

        return pe, section

    def _clone_exports(self, tgt, eat: ExportDataDirectory, new_section_name='.rdata2'):

        # Forwards don't typically supply the extension
        tgt = copy.deepcopy(tgt)
        new_eat_size = len(eat.compile())

        tgt, obj = self.add_section(tgt, new_section_name, new_eat_size)
        # tgt, section = self.replace_section(tgt, ".rdata", new_eat_size)
        final_rva = obj.VirtualAddress
        eat.reset_base_address(final_rva)

        # Write in our new export directory
        tgt.set_bytes_at_rva(
            final_rva,
            eat.compile()
        )

        # Rebuild from bytes to save back
        tgt = pefile.PE(data=tgt.__data__)

        # Update directory specs
        tgt_export_dir = tgt.OPTIONAL_HEADER.DATA_DIRECTORY[0]
        tgt_export_dir.VirtualAddress = obj.VirtualAddress
        tgt_export_dir.Size = new_eat_size
        tgt = pefile.PE(data=tgt.write())

        return tgt

    def clone_exports(self, source, destination, path=None, section_name=".rdata2", preserve=True):
        if not path:
            path = source
        with open(destination, "rb") as d:
            target_pe = pefile.PE(data=d.read())

        if self.debug:
            print('[+] Loaded files')

        binary = lief.parse(source)
        export = binary.get_export()
        print(binary.__dir__())

        if len(export.entries) == 0:
            raise Exception('Reference binary has no exports')

        # We copy the source DLL of course
        dll_name = Path(path).absolute().resolve()
        spoof_name = Path(destination).absolute().resolve()
        eat = ExportDataDirectory(dll_name=dll_name)
        eat.set_timestamp(export.timestamp)
        eat.characteristics = 0
        ordinals = []

        # If we want to preserve the target DLL symbols
        if preserve:
            dlls = [destination, source]
        else:
            dlls = [source]

        seen = []
        for target in dlls:
            binary = lief.parse(target)
            exports = binary.get_export()
            # for e in filter(lambda x: not x.is_forwarded, exports.entries):
            if exports:
                for e in exports.entries:
                    if target == destination and not e.is_forwarded:
                        eat.add_function(e.name, e.address)
                        ordinals.append(e.ordinal)
                        seen.append(e.name)
                    else:
                        name = e.name.split(".")[-1]
                        if name not in seen:
                            # This prevents overwriting non-proxied calls
                            eat.add_forwarded_function(name)
                            seen.append(name)

        # We also preserve the Target DLL base
        eat.base = min(ordinals) if len(ordinals) > 0 else 0
        print(eat.compile())

        # cloned_pe = self._clone_exports(target_pe, eat, section_name)
        cloned_pe = self._clone_exports(target_pe, eat, section_name)

        cloned_bytes = cloned_pe.write()
        with open(destination, 'wb') as out:
            out.write(cloned_bytes)

        if self.debug:
            print('[+] Done: {}'.format(destination))


def main(arguments):
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('target', help="Target DLL for modifications")
    parser.add_argument('reference', help="Reference DLL from which the exports will be cloned")
    parser.add_argument('-o', '--out', default=None,
                        help="Output file path (Default = <target>.clone.dll)")
    parser.add_argument('-p', '--path', default=None,
                        help="Full path to reference DLL while being hijacked (if <reference> is not accurate)")
    parser.add_argument('-s', '--section-name', default=".rdata2",
                        help="New section name (Default = .rdata2)")
    parser.add_argument('-A', '--preserve', default=False, action="store_true",
                        help="Preserve target DLL exports")
    args = parser.parse_args(arguments)

    koppeling = KoppelingNG()

    if not args.path:
        args.path = args.reference

    if not args.out:
        args.out = args.target + '.clone.dll'

    koppeling.clone_exports(args.reference, args.target, args.path, args.section_name, args.preserve)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
