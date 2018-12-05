from common import constants
from common import utils
from common.constants import TEXT, RODATA, DATA, BSS, INIT, STRTAB
from common.constants import FINI, PLT, DYNSYM, DYNSTR, GOTPLT, SYMTAB


class Sections:
    def __init__(self, *args, **kwargs):
        self.binary = kwargs['binary']
        self.sections = dict()
        sec = self.binary.elffile.get_section_by_name(TEXT)
        if sec is None:
            raise Exception('No .text section in the binary.')
        self.sections[TEXT] = TextSection(data=sec.data(), addr=sec['sh_addr'], binary=self.binary)
        if self.binary.elffile.get_section_by_name(RODATA):
            sec = self.binary.elffile.get_section_by_name(RODATA)
            self.sections[RODATA] = RodataSection(data=sec.data(), addr=sec['sh_addr'], binary=self.binary)
        if self.binary.elffile.get_section_by_name(DATA):
            sec = self.binary.elffile.get_section_by_name(DATA)
            self.sections[DATA] = SectionWithoutData(addr=sec['sh_addr'], data_size=sec.data_size, binary=self.binary)
        if self.binary.elffile.get_section_by_name(BSS):
            sec = self.binary.elffile.get_section_by_name(BSS)
            self.sections[BSS] = SectionWithoutData(addr=sec['sh_addr'], data_size=sec.data_size, binary=self.binary)
        if self.binary.elffile.get_section_by_name(INIT):
            sec = self.binary.elffile.get_section_by_name(INIT)
            self.sections[INIT] = SectionWithoutData(addr=sec['sh_addr'], data_size=sec.data_size, binary=self.binary)
        if self.binary.elffile.get_section_by_name(FINI):
            sec = self.binary.elffile.get_section_by_name(FINI)
            self.sections[FINI] = SectionWithoutData(addr=sec['sh_addr'], data_size=sec.data_size, binary=self.binary)
        if self.binary.elffile.get_section_by_name(PLT):
            sec = self.binary.elffile.get_section_by_name(PLT)
            self.sections[PLT] = SectionWithoutData(addr=sec['sh_addr'], data_size=sec.data_size, binary=self.binary)
        if self.binary.elffile.get_section_by_name(GOTPLT):
            sec = self.binary.elffile.get_section_by_name(GOTPLT)
            self.sections[GOTPLT] = GotPltSection(data=sec.data(), addr=sec['sh_addr'], binary=self.binary)
        if self.binary.elffile.get_section_by_name(DYNSYM):
            self.sections[DYNSYM] = self.binary.elffile.get_section_by_name(DYNSYM)
        if self.binary.elffile.get_section_by_name(DYNSTR):
            self.sections[DYNSTR] = self.binary.elffile.get_section_by_name(DYNSTR)
        if self.binary.elffile.get_section_by_name(SYMTAB):
            self.sections[SYMTAB] = self.binary.elffile.get_section_by_name(SYMTAB)

        self.symbol_names = set()
        self.init_symbol_names()

    def init_symbol_names(self):
        if self.has_sec(DYNSYM) and self.has_sec(DYNSTR):
            dynsym = self.get_sec(DYNSYM)
            dynstr = self.get_sec(DYNSTR)
            if hasattr(dynsym, 'iter_symbols'):
                for sym in dynsym.iter_symbols():
                    name = dynstr.get_string(sym.entry['st_name'])
                    if '@@' in name:
                        name = name[:name.find('@@')]
                    if '.' in name:
                        name = name[:name.find('.')]
                    self.symbol_names.add(name)
        
        symtab = self.binary.elffile.get_section_by_name(SYMTAB)
        strtab = self.binary.elffile.get_section_by_name(STRTAB)

        if symtab is not None \
                and strtab is not None \
                and self.binary.config.MODE == self.binary.config.TEST:
            if hasattr(symtab, 'iter_symbols'):
                for sym in symtab.iter_symbols():
                    name = strtab.get_string(sym.entry['st_name'])
                    if '@@' in name:
                        name = name[:name.find('@@')]
                    if '.' in name:
                        name = name[:name.find('.')]
                    self.symbol_names.add(name)

                    ttype = sym.entry['st_info']['type']
                    value = sym.entry['st_value']
                    if ttype == 'STT_OBJECT' and value in self.binary.direct_offsets:
                        direct_offset = self.binary.direct_offsets[value]
                        direct_offset.name = name
                        direct_offset.train_name = name
                        direct_offset.test_name = name
                        direct_offset.is_name_given = True

    def has_sec(self, sec_name):
        return sec_name in self.sections

    def get_sec(self, sec_name):
        return self.sections[sec_name]

    def is_in_bss_sec(self, addr):
        return (BSS in self.sections) and (self.sections[BSS].is_in_sec(addr))

    def is_in_data_sec(self, addr):
        return (DATA in self.sections) and (self.sections[DATA].is_in_sec(addr))

    def is_in_rodata_sec(self, addr):
        return (RODATA in self.sections) and (self.sections[RODATA].is_in_sec(addr))

    def is_in_init_sec(self, addr):
        return (INIT in self.sections) and (self.sections[INIT].is_in_sec(addr))

    def is_in_fini_sec(self, addr):
        return (FINI in self.sections) and (self.sections[FINI].is_in_sec(addr))

    def get_rodata_string(self, addr):
        return self.sections[RODATA].get_string(addr) if RODATA in self.sections else ''

    def get_rodata_addrs(self, addr):
        return self.sections[RODATA].get_rodata_addrs(addr) if RODATA in self.sections else []

    def get_text_addrs(self, addr):
        return self.sections[RODATA].get_text_addrs(addr) if RODATA in self.sections else []

    def is_in_text_sec(self, addr):
        return (TEXT in self.sections) and (self.sections[TEXT].is_in_sec(addr))

    def is_in_plt_sec(self, addr):
        return (PLT in self.sections) and (self.sections[PLT].is_in_sec(addr))

    def is_in_gotplt_sec(self, addr):
        return (GOTPLT in self.sections) and (self.sections[GOTPLT].is_in_sec(addr))

    def get_gotplt_offset(self, addr):
        return addr if GOTPLT not in self.sections else self.sections[GOTPLT].get_offset(addr)

    def init_dynsym_functions(self):
        if self.has_sec(DYNSYM) and self.has_sec(DYNSTR):
            dynsym = self.get_sec(DYNSYM)
            dynstr = self.get_sec(DYNSTR)
            if hasattr(dynsym, 'iter_symbols'):
                for sym in dynsym.iter_symbols():
                    ttype = sym.entry['st_info']['type']
                    name = dynstr.get_string(sym.entry['st_name'])
                    if '@' in name:
                        name = name[:name.find('@')]
                    value = sym.entry['st_value']

                    if ttype == 'STT_FUNC' and self.binary.functions.is_lowpc_function(value):
                        function = self.binary.functions.get_function_by_lowpc(value)
                        function.name = name
                        function.train_name = name
                        function.test_name = name
                        function.is_name_given = True
                        if self.is_in_text_sec(value):
                            function.is_run_init = True
                        else:
                            function.is_run_init = False

    def init_dynsym_offsets(self):
        if self.has_sec(DYNSYM) and self.has_sec(DYNSTR):
            dynsym = self.get_sec(DYNSYM)
            dynstr = self.get_sec(DYNSTR)
            if hasattr(dynsym, 'iter_symbols'):
                for sym in dynsym.iter_symbols():
                    ttype = sym.entry['st_info']['type']
                    name = dynstr.get_string(sym.entry['st_name'])
                    if '@@' in name:
                        name = name[:name.find('@@')]
                    if '.' in name:
                        name = name[:name.find('.')]
                    value = sym.entry['st_value']

                    if ttype == 'STT_OBJECT' and value in self.binary.direct_offsets:
                        direct_offset = self.binary.direct_offsets[value]
                        direct_offset.name = name
                        direct_offset.train_name = name
                        direct_offset.test_name = name
                        direct_offset.is_name_given = True


class Section:
    def __init__(self, *args, **kwargs):
        self.addr = kwargs['addr']
        self.binary = kwargs['binary']
        self.end_addr = None

    def is_in_sec(self, addr):
        return (addr >= self.addr) and (addr < self.end_addr)


class SectionWithData(Section):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data = kwargs['data']
        self.end_addr = self.addr + len(self.data)


class SectionWithoutData(Section):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.end_addr = self.addr + kwargs['data_size']


class RodataSection(SectionWithData):
    def get_rodata_addrs(self, addr):
        if not self.is_in_sec(addr):
            return None

        off = addr - self.addr
        addrs = []

        while off < len(self.data) and (off + self.binary.config.ADDRESS_BYTE_SIZE) < len(self.data):
            a = utils.decode_address(self.data[off:], self.binary)
            if self.is_in_sec(a):
                addrs.append(a)
            else:
                break
            off += self.binary.config.ADDRESS_BYTE_SIZE

        return addrs

    def get_text_addrs(self, addr):
        if not self.is_in_sec(addr):
            return None

        off = addr - self.addr
        addrs = []

        while off < len(self.data) and (off + self.binary.config.ADDRESS_BYTE_SIZE) < len(self.data):
            a = utils.decode_address(self.data[off:], self.binary)
            if self.binary.sections.is_in_text_sec(a):
                addrs.append(a)
            else:
                break
            off += self.binary.config.ADDRESS_BYTE_SIZE

        return addrs

    def get_string(self, addr):
        if not self.is_in_sec(addr):
            return None

        off = addr - self.addr

        txt = []
        c = 0
        i = 0
        while off < len(self.data):
            c = self.data[off]
            if c == 0:
                break
            if c not in constants.BYTES_PRINTABLE_SET:
                break
            txt.append(utils.get_char(c))
            off += 1
            i += 1

        if c != 0 or i == 0:
            return None
        else:
            return ''.join(txt)


class TextSection(SectionWithData):
    def get_data_offset(self, addr):
        byte_size = self.binary.config.ADDRESS_BYTE_SIZE
        if self.is_in_sec(addr) and self.is_in_sec(addr + byte_size):
            off = addr - self.addr
            addr = utils.decode_address(self.data[off:off + byte_size], self.binary)
        return addr


class GotPltSection(SectionWithData):
    def get_offset(self, addr):
        byte_size = self.binary.config.ADDRESS_BYTE_SIZE
        if self.is_in_sec(addr) and self.is_in_sec(addr + byte_size):
            off = addr - self.addr
            addr = utils.decode_address(self.data[off:off + byte_size], self.binary)
        return addr
