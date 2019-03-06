from common.constants import UNKNOWN_LABEL, ENUM_DW_FORM_exprloc, VOID, TTYPES
from common.constants import TEXT, RODATA, DATA, BSS, INIT, FINI, PLT, GOTPLT, GOT, PLTGOT
from common import utils
from elements.regs import Reg
from elements.offsets import IndirectOffset, DirectOffset


class StringTable:

    def __init__(self, *args, **kwargs):
        self.binary = kwargs['binary']
        self.str_to_offset = dict()
        self.content = bytearray()
        self.content.append(0x0)

    def get_offset(self, s):
        if s in self.str_to_offset:
            return self.str_to_offset[s]
        else:
            off = len(self.content)
            self.content += bytearray(map(ord, s))
            self.content.append(0x0)
            return off


class SymbolTable:

    def __init__(self, *args, **kwargs):
        self.binary = kwargs['binary']
        self.content = bytearray()
        self.num_entries = 0

    def debug_info(self):
        self.content += utils.encode_kbytes(0, 4)
        self.content += utils.encode_address(0, self.binary)
        self.content += utils.encode_address(0, self.binary)
        self.content.append(0x0)
        self.content.append(0x0)
        self.content.append(0x0)
        self.content.append(0x0)

        for function in self.binary.functions.functions:
            if function.test_name != UNKNOWN_LABEL:

                self.num_entries += 1

                name_off = self.binary.string_table.get_offset(function.test_name)
                self.content += utils.encode_kbytes(name_off, 4)

                if self.binary.sections.is_in_text_sec(function.low_pc):
                    sec_idx = self.binary.elffile._section_name_map[TEXT]
                elif self.binary.sections.is_in_init_sec(function.low_pc):
                    sec_idx = self.binary.elffile._section_name_map[INIT]
                elif self.binary.sections.is_in_fini_sec(function.low_pc):
                    sec_idx = self.binary.elffile._section_name_map[FINI]
                elif self.binary.sections.is_in_plt_sec(function.low_pc):
                    sec_idx = self.binary.elffile._section_name_map[PLT]
                elif self.binary.sections.is_in_gotplt_sec(function.low_pc):
                    sec_idx = self.binary.elffile._section_name_map[GOTPLT]
                elif self.binary.sections.is_in_got_sec(function.low_pc):
                    sec_idx = self.binary.elffile._section_name_map[GOT]
                elif self.binary.sections.is_in_pltgot_sec(function.low_pc):
                    sec_idx = self.binary.elffile._section_name_map[PLTGOT]
                else:
                    print(self.binary.name)
                    print(hex(function.low_pc))
                    print(function.test_name)
                    assert False, 'Function appears in section other than .text, .init, .fini, .plt, .got.plt, .got and .plt.got'

                if self.binary.config.MACHINE_ARCH == 'x64':
                    self.content.append((0x1 << 4) + 0x2)
                    self.content.append(0x0)
                    self.content.append(sec_idx)
                    self.content.append(0x0)

                self.content += utils.encode_address(function.low_pc, self.binary)
                self.content += utils.encode_address(function.high_pc - function.low_pc, self.binary)

                if self.binary.config.MACHINE_ARCH in ('x86', 'ARM'):
                    self.content.append((0x1 << 4) + 0x2)
                    self.content.append(0x0)
                    self.content.append(sec_idx)
                    self.content.append(0x0)

        for off in sorted(self.binary.direct_offsets.keys()):
            direct_offset = self.binary.direct_offsets[off]
            if direct_offset.test_name is not None \
                    and direct_offset.test_name != UNKNOWN_LABEL:

                self.num_entries += 1

                name_off = self.binary.string_table.get_offset(direct_offset.test_name)
                self.content += utils.encode_kbytes(name_off, 4)

                if self.binary.config.MACHINE_ARCH == 'x64':
                    self.content.append((0x1 << 4) + 0x1)
                    self.content.append(0x0)
                    if self.binary.sections.is_in_data_sec(off):
                        self.content.append(self.binary.elffile._section_name_map[DATA])
                    elif self.binary.sections.is_in_bss_sec(off):
                        self.content.append(self.binary.elffile._section_name_map[BSS])
                    elif self.binary.sections.is_in_rodata_sec(off):
                        self.content.append(self.binary.elffile._section_name_map[RODATA])
                    else:
                        print(format(off, '02x'))
                        assert False, 'Direct Offset appears in section other than .data and .bss.'
                    self.content.append(0x0)

                self.content += utils.encode_address(off, self.binary)
                ttype = direct_offset.ttype
                if ttype.test_name is None \
                        or ttype.test_name in (UNKNOWN_LABEL, VOID) \
                        or ttype.test_name not in TTYPES:
                    self.content += utils.encode_address(4, self.binary)
                else:
                    t = self.binary.types.get_type(ttype.test_name)
                    if t is None or not hasattr(t, 'byte_size'):
                        self.content += utils.encode_address(0, self.binary)
                    else:
                        self.content += utils.encode_address(t.byte_size, self.binary)

                if self.binary.config.MACHINE_ARCH in ('x86', 'ARM'):
                    self.content.append((0x1 << 4) + 0x1)
                    self.content.append(0x0)
                    if self.binary.sections.is_in_data_sec(off):
                        self.content.append(self.binary.elffile._section_name_map['.data'])
                    elif self.binary.sections.is_in_bss_sec(off):
                        self.content.append(self.binary.elffile._section_name_map['.bss'])
                    elif self.binary.sections.is_in_rodata_sec(off):
                        self.content.append(self.binary.elffile._section_name_map['.rodata'])
                    else:
                        print(format(off, '02x'))
                        assert False, 'Direct Offset appears in section other than .data and .bss.'
                    self.content.append(0x0)


class AbstractLoc:

    def __init__(self, *args, **kwargs):
        self.loc = kwargs['loc']
        self.pc = kwargs['pc']

    def __eq__(self, other):
        return self.pc == other.pc \
            and self.loc == other.loc

    def __lt__(self, other):
        return self.pc < other.pc


class DebugLoc:

    def __init__(self, *args, **kwargs):
        self.content = bytearray()
        self.binary = kwargs['binary']

    def loc_to_content(self, start, end):
        self.content += utils.encode_address(start.pc - self.binary.low_pc, self.binary)
        self.content += utils.encode_address(self.binary.insn_map.get_pc(end.pc) - self.binary.low_pc, self.binary)

        if isinstance(start.loc, Reg):
            self.content.append(0x01)
            self.content.append(0x00)
            self.content.append(self.binary.config.REG_MAPPING[start.loc.base_register] +
                                ENUM_DW_FORM_exprloc['DW_OP_reg0'])
        elif isinstance(start.loc, IndirectOffset):
            loc_expr = bytearray()
            loc_expr.append(self.binary.config.REG_MAPPING[start.loc.base_pointer] +
                            ENUM_DW_FORM_exprloc['DW_OP_breg0'])
            loc_expr += utils.encode_sleb128(start.loc.offset)
            length = len(loc_expr)
            self.content.append(length & 0xff)
            length = length >> 8
            self.content.append(length & 0xff)
            self.content += loc_expr
        elif isinstance(start.loc, DirectOffset):
            self.content.append(self.binary.config.ADDRESS_BYTE_SIZE + 1)
            self.content.append(0x00)
            self.content.append(ENUM_DW_FORM_exprloc['DW_OP_addr'])
            self.content += utils.encode_address(start.loc.offset, self.binary)
        else:
            assert False, 'reached an unimplemented branch'

    def add_locs(self, locs):
        locs = sorted(locs, key=lambda l: l.low_pc)

        loc_heap = list()

        for loc in locs:
            for pc in loc.pcs:
                loc_heap.append(AbstractLoc(loc=loc, pc=pc))

        loc_heap = sorted(loc_heap, reverse=True)

        start = None
        end = None

        while len(loc_heap) > 0:
            current = loc_heap.pop()

            if start is None:
                start = current
                end = current

            is_different = True
            if isinstance(start.loc, Reg) \
                    and isinstance(current.loc, Reg) \
                    and start.loc.base_register == current.loc.base_register:
                end = current
                is_different = False
            elif isinstance(start.loc, IndirectOffset) \
                    and isinstance(current.loc, IndirectOffset) \
                    and start.loc.base_pointer == current.loc.base_pointer \
                    and start.loc.offset == current.loc.offset:
                end = current
                is_different = False
            elif isinstance(start.loc, DirectOffset) \
                    and isinstance(current.loc, DirectOffset) \
                    and start.loc.offset == current.loc.offset:
                end = current
                is_different = False

            if is_different or len(loc_heap) == 0:
                self.loc_to_content(start, end)

                start = current
                end = current

            if is_different and len(loc_heap) == 0:
                self.loc_to_content(start, end)

        self.content += bytearray([0 for i in range(0, 2 * self.binary.config.ADDRESS_BYTE_SIZE)])
