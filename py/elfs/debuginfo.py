import traceback
import sys
import ctypes

from common import utils

from elfs.framebase import FrameBase

from elftools.dwarf.callframe import ZERO
from elftools.dwarf.locationlists import LocationEntry
from elftools.elf.elffile import ELFFile

from elements.regs import GivReg

from common.constants import UNKNOWN_LABEL
from common.constants import ENUM_DW_FORM_exprloc, ENUM_DW_TAG, ENUM_DW_AT, ENUM_DW_FORM
from common.constants import ENUM_ABBREV_CODE, ENUM_DW_CHILDREN, ENUM_DW_AT_language
from common.constants import POINTER, ENUM, ARRAY, UNION, STRUCT, VOID
from common.constants import SHORT, UNSIGNED_SHORT, CHAR, UNSIGNED_CHAR, LONG_LONG
from common.constants import UNSIGNED_LONG_LONG, LONG, UNSIGNED_LONG
from common.constants import INT, UNSIGNED_INT, BOOL
from common.constants import TEXT, RODATA, DATA, BSS, MAX_UPPER_BOUND
from common.constants import SYMTAB, STRTAB

from common.utils import decode_sleb128, decode_uleb128, decode_address, encode_address


class DebugInfo:
    def __init__(self, *args, **kwargs):
        self.binary = kwargs['binary']
        self.dies = dict()

        self.debug_elffile = ELFFile(kwargs['debug_elffile'])

        if self.debug_elffile.has_dwarf_info():
            self.dwarf_info = self.debug_elffile.get_dwarf_info()
            self.location_lists = self.dwarf_info.location_lists()

        self.symtab = self.debug_elffile.get_section_by_name(SYMTAB)
        self.strtab = self.debug_elffile.get_section_by_name(STRTAB)

        self.call_frames = []
        self.init_call_frames()

    def init_call_frames(self):
        cfi_entries = []
        if self.binary.elffile.get_dwarf_info().has_EH_CFI():
            cfi_entries += self.binary.elffile.get_dwarf_info().EH_CFI_entries()
        if self.dwarf_info.has_CFI():
            cfi_entries += self.dwarf_info.CFI_entries()

        call_frames = []
        for entry in cfi_entries:
            if not isinstance(entry, ZERO):
                for row in entry.get_decoded().table:
                    cfa = row['cfa']
                    pc = row['pc']
                    if cfa.reg is not None and cfa.offset is not None and cfa.reg in self.binary.config.REG_MAPPING:
                        call_frames.append(FrameBase(base_register=self.binary.config.REG_MAPPING[cfa.reg], offset=cfa.offset, low_pc=pc, high_pc=None))
        call_frames = sorted(call_frames, key=lambda f: f.low_pc)
        for i, frame in enumerate(call_frames):
            if i < len(call_frames) - 1:
                frame.high_pc = call_frames[i + 1].low_pc - 1
        if len(call_frames) > 0:
            call_frames[-1].high_pc = self.binary.config.HIGH_PC
        self.call_frames = call_frames

    def get_pointer_ttype_die(self, die):
        die_type_offset = die.attributes.get('DW_AT_type', None)
        cu_offset = die.cu.cu_offset
        die_type = None
        if die_type_offset is not None and die_type_offset.value + cu_offset in self.dies:
            die_type = self.dies[die_type_offset.value + cu_offset]
        else:
            abstract_origin_attr = die.attributes.get('DW_AT_abstract_origin', None)
            specification_attr = die.attributes.get('DW_AT_specification', None)
            if abstract_origin_attr is not None:
                origin_offset = abstract_origin_attr.value + die.cu.cu_offset
                return self.get_pointer_ttype_die(self.dies[origin_offset])
            elif specification_attr is not None:
                specification_offset = specification_attr.value + die.cu.cu_offset
                return self.get_pointer_ttype_die(self.dies[specification_offset])
        if die_type is None:
            return None
        else:
            if die.tag == 'DW_TAG_pointer_type':
                return die_type
            else:
                return self.get_pointer_ttype_die(die_type)

    def get_ttype_name(self, die):
        if die.tag == 'DW_TAG_pointer_type':
            return POINTER
        elif die.tag == 'DW_TAG_enumeration_type':
            return ENUM
        elif die.tag == 'DW_TAG_array_type':
            return ARRAY
        elif die.tag == 'DW_TAG_union_type':
            return UNION
        elif die.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type'):
            return STRUCT
        elif die.tag == 'DW_TAG_base_type':
            type_name_attr = die.attributes.get('DW_AT_name', None)
            if type_name_attr is None:
                return VOID
            else:
                type_name = type_name_attr.value.decode('ascii')
                if 'short' in type_name:
                    if 'unsigned' in type_name:
                        return UNSIGNED_SHORT
                    else:
                        return SHORT
                elif 'char' in type_name:
                    if 'unsigned' in type_name:
                        return UNSIGNED_CHAR
                    else:
                        return CHAR
                elif type_name.count('long') == 2:
                    if 'unsigned' in type_name:
                        return UNSIGNED_LONG_LONG
                    else:
                        return LONG_LONG
                elif type_name.count('long') == 1:
                    if 'unsigned' in type_name:
                        return UNSIGNED_LONG
                    else:
                        return LONG
                elif 'int' in type_name:
                    if 'unsigned' in type_name:
                        return UNSIGNED_INT
                    else:
                        return INT
                elif 'bool' in type_name.lower():
                    return BOOL
                else:
                    return VOID
        else:  # ('DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type'):
            die_type_offset = die.attributes.get('DW_AT_type', None)
            cu_offset = die.cu.cu_offset
            if die_type_offset is not None and die_type_offset.value + cu_offset in self.dies:
                die_type = self.dies[die_type_offset.value + cu_offset]
                return self.get_ttype_name(die_type)
            else:
                abstract_origin_attr = die.attributes.get('DW_AT_abstract_origin', None)
                specification_attr = die.attributes.get('DW_AT_specification', None)
                if abstract_origin_attr is not None:
                    origin_offset = abstract_origin_attr.value + die.cu.cu_offset
                    return self.get_ttype_name(self.dies[origin_offset])
                elif specification_attr is not None:
                    specification_offset = specification_attr.value + die.cu.cu_offset
                    return self.get_ttype_name(self.dies[specification_offset])
                else:
                    return VOID

    def get_name_origin(self, die):
        name_attr = die.attributes.get('DW_AT_name', None)
        abstract_origin_attr = die.attributes.get('DW_AT_abstract_origin', None)
        specification_attr = die.attributes.get('DW_AT_specification', None)
        cu_offset = die.cu.cu_offset
        if name_attr is None:
            if abstract_origin_attr is not None:
                origin_offset = abstract_origin_attr.value + cu_offset
                return self.get_name_origin(self.dies[origin_offset])
            elif specification_attr is not None:
                origin_offset = specification_attr.value + cu_offset
                return self.get_name_origin(self.dies[origin_offset])
            else:
                return die
        else:
            return die

    def get_die_type(self, die):
        if die is None:
            return None

        die_type_offset = die.attributes.get('DW_AT_type', None)
        cu_offset = die.cu.cu_offset
        if die_type_offset is None:
            abstract_origin_attr = die.attributes.get('DW_AT_abstract_origin', None)
            specification_attr = die.attributes.get('DW_AT_specification', None)
            if abstract_origin_attr is not None:
                origin_offset = abstract_origin_attr.value + cu_offset
                return self.get_die_type(self.dies[origin_offset])
            elif specification_attr is not None:
                origin_offset = specification_attr.value + cu_offset
                return self.get_die_type(self.dies[origin_offset])
            else:
                return die
        else:
            die_type = self.dies[die_type_offset.value + cu_offset]
            if die_type.tag in ('DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type'):
                return self.get_die_type(die_type)
            else:
                return die_type

    def get_byte_size(self, die):
        byte_size_attr = die.attributes.get('DW_AT_byte_size', None)
        if byte_size_attr is not None:
            return byte_size_attr.value
        else:
            type_offset_attr = die.attributes.get('DW_AT_type', None)
            if type_offset_attr is None:
                return None
            else:
                cu_offset = die.cu.cu_offset
                offset = type_offset_attr.value + cu_offset
                if offset not in self.dies:
                    return None
                else:
                    return self.get_byte_size(self.dies[offset])

    def get_array_upper_bound(self, die):
        for child in die.iter_children():
            if child.tag == 'DW_TAG_subrange_type':
                upper_bound_attr = child.attributes.get('DW_AT_upper_bound', None)
                if upper_bound_attr is None:
                    return None
                else:
                    if upper_bound_attr.form in ('DW_FORM_data1',
                                                 'DW_FORM_data2',
                                                 'DW_FORM_data4',
                                                 'DW_FORM_data8'):
                        return upper_bound_attr.value
                    elif upper_bound_attr.form == 'DW_FORM_exprloc':
                        loc = upper_bound_attr.value
                        if loc[0] == ENUM_DW_FORM_exprloc['DW_OP_const1u']:
                            return ctypes.c_uint8(loc[1]).value
                        elif loc[0] == ENUM_DW_FORM_exprloc['DW_OP_const1s']:
                            return ctypes.c_int8(loc[1]).value
                        elif loc[0] == ENUM_DW_FORM_exprloc['DW_OP_const2u']:
                            return ctypes.c_uint16(utils.decode_kbytes(loc[1:], 2)).value
                        elif loc[0] == ENUM_DW_FORM_exprloc['DW_OP_const2s']:
                            return ctypes.c_int16(utils.decode_kbytes(loc[1:], 2)).value
                        elif loc[0] == ENUM_DW_FORM_exprloc['DW_OP_const4u']:
                            return ctypes.c_uint32(utils.decode_kbytes(loc[1:], 2)).value
                        elif loc[0] == ENUM_DW_FORM_exprloc['DW_OP_const4s']:
                            return ctypes.c_int32(utils.decode_kbytes(loc[1:], 2)).value
                        elif loc[0] == ENUM_DW_FORM_exprloc['DW_OP_const8u']:
                            return ctypes.c_uint64(utils.decode_kbytes(loc[1:], 2)).value
                        elif loc[0] == ENUM_DW_FORM_exprloc['DW_OP_const8s']:
                            return ctypes.c_int64(utils.decode_kbytes(loc[1:], 2)).value
                        elif loc[0] == ENUM_DW_FORM_exprloc['DW_OP_constu']:
                            return utils.decode_uleb128(loc[1:])
                        elif loc[0] == ENUM_DW_FORM_exprloc['DW_OP_consts']:
                            return utils.decode_sleb128(loc[1:])
                        else:
                            return None
                    else:
                        return None

    def binary_train_info(self):
        for cu in self.dwarf_info.iter_CUs():
            for die in cu.iter_DIEs():
                self.dies[die.offset] = die

        added_die = set()
        for cu in self.dwarf_info.iter_CUs():
            top_die = cu.get_top_DIE()
            low_pc_attr = top_die.attributes.get('DW_AT_low_pc', None)
            if low_pc_attr is not None:
                cu_low_pc = low_pc_attr.value
            else:
                cu_low_pc = 0

            for die in cu.iter_DIEs():
                if die.tag == 'DW_TAG_subprogram':
                    low_pc_attr = die.attributes.get('DW_AT_low_pc', None)
                    # high_pc_attr = die.attributes.get('DW_AT_high_pc', None)
                    origin = self.get_name_origin(die)
                    if low_pc_attr is not None:
                        low_pc = low_pc_attr.value
                        if self.binary.functions.is_lowpc_function(low_pc):
                            function = self.binary.functions.get_function_by_lowpc(low_pc)
                            if function.is_run_init:
                                self.function_train_info(function, die, cu_low_pc, True)
                                added_die.add(die)
                        else:
                            pass
                    else:
                        pass
                if die.tag == 'DW_TAG_variable':
                    loc_attr = die.attributes.get('DW_AT_location', None)
                    if loc_attr is not None:
                        loc = loc_attr.value
                        form = loc_attr.form
                        if form == 'DW_FORM_block1' or form == 'DW_FORM_exprloc':
                            if loc[0] == ENUM_DW_FORM_exprloc['DW_OP_addr'] and len(loc) == self.binary.config.ADDRESS_BYTE_SIZE + 1:
                                offset = utils.decode_address(loc[1:], self.binary)
                                self.direct_offset_train_info(offset, die)
                            else:
                                pass
                        else:
                            pass
                    else:
                        pass

        for sym in self.symtab.iter_symbols():
            ttype = sym.entry['st_info']['type']
            name = self.strtab.get_string(sym.entry['st_name'])
            if '@@' in name:
                name = name[:name.find('@@')]
            value = sym.entry['st_value']

            if ttype == 'STT_FUNC' and self.binary.functions.is_lowpc_function(value):
                function = self.binary.functions.get_function_by_lowpc(value)
                if function.train_name == UNKNOWN_LABEL:
                    function.train_name = name

            if ttype == 'STT_OBJECT' and value in self.binary.direct_offsets:
                direct_offset = self.binary.direct_offsets[value]
                if direct_offset.train_name == UNKNOWN_LABEL:
                    direct_offset.train_name = name

        for cu in self.dwarf_info.iter_CUs():
            top_die = cu.get_top_DIE()
            low_pc_attr = top_die.attributes.get('DW_AT_low_pc', None)
            if low_pc_attr is not None:
                cu_low_pc = low_pc_attr.value
            else:
                cu_low_pc = 0

            for die in cu.iter_DIEs():
                if die.tag == 'DW_TAG_subprogram':

                    origin = self.get_name_origin(die)
                    name_attr = origin.attributes.get('DW_AT_name', None)
                    if name_attr is not None:
                        name = name_attr.value.decode('ascii')
                        for function in self.binary.functions.functions:
                            if function.is_run_init \
                                    and (function.name == name or function.train_name == name):
                                self.function_train_info(function, die, cu_low_pc, True)
                                break

                    die_linkage_name_attr = die.attributes.get('DW_AT_linkage_name', None)
                    origin_linkage_name_attr = origin.attributes.get('DW_AT_linkage_name', None)
                    name = None
                    if die_linkage_name_attr is not None:
                        name = die_linkage_name_attr.value.decode('ascii')
                    elif origin_linkage_name_attr is not None:
                        name = origin_linkage_name_attr.value.decode('ascii')

                    if name is not None:
                        for function in self.binary.functions.functions:
                            if function.is_run_init \
                                    and (function.name == name or function.train_name == name):
                                self.function_train_info(function, die, cu_low_pc, True)
                                break

                if die.tag == 'DW_TAG_variable':
                    origin = self.get_name_origin(die)
                    name_attr = origin.attributes.get('DW_AT_name', None)
                    if name_attr is not None:
                        name = name_attr.value.decode('ascii')
                        for direct_offset in self.binary.direct_offsets.values():
                            if direct_offset.train_name == name \
                                    and direct_offset.ttype.train_name == UNKNOWN_LABEL:
                                ttype = self.get_ttype_name(die)
                                direct_offset.ttype.train_info(ttype)

        # for f in self.binary.functions.functions:
        #     if f.train_name != UNKNOWN_LABEL \
        #             and f.ttype.train_name == UNKNOWN_LABEL:
        #         f.ttype.train_info(VOID)

    def function_train_info(self, function, die, cu_low_pc, add_info):
        frame_base_attr = die.attributes.get('DW_AT_frame_base', None)
        function.add_frame_bases(frame_base_attr, cu_low_pc)
        function.init_run = True

        if add_info:
            name = self.get_ttype_name(die)
            function.ttype.train_info(name)

            origin = self.get_name_origin(die)
            name_attr = origin.attributes.get('DW_AT_name', None)
            if name_attr is not None:
                function.train_name = name_attr.value.decode('ascii')

        descendants = []

        def get_die_descendants(d):
            if d.tag in ('DW_TAG_inlined_subroutine', 'DW_TAG_GNU_call_site'):
                pass
            else:
                if d.tag in ('DW_TAG_formal_parameter', 'DW_TAG_variable'):
                    descendants.append(d)
                for child in d.iter_children():
                    get_die_descendants(child)

        get_die_descendants(die)

        for desc in descendants:
            if desc.tag in ('DW_TAG_formal_parameter', 'DW_TAG_variable'):
                loc_attr = desc.attributes.get('DW_AT_location', None)
                if loc_attr is not None:
                    loc = loc_attr.value
                    form = loc_attr.form
                    if form == 'DW_FORM_exprloc':
                        self.loc_train_info(function, loc, desc)
                    elif form in ('DW_FORM_data4', 'DW_FORM_sec_offset'):
                        self.location_list_train_info(function, loc, desc, cu_low_pc)
                    elif form == 'DW_FORM_block1':
                        if len(loc) == 1:
                            if ENUM_DW_FORM_exprloc['DW_OP_reg0'] <= loc[0] <= ENUM_DW_FORM_exprloc['DW_OP_reg31'] \
                                    and (loc[0] - ENUM_DW_FORM_exprloc['DW_OP_reg0']) in self.binary.config.REG_MAPPING:
                                base_register = self.binary.config.REG_MAPPING[loc[0] - ENUM_DW_FORM_exprloc['DW_OP_reg0']]
                                self.reg_add_info(function, base_register, desc, None, None)
                        else:
                            self.loc_train_info(function, loc, desc)
                    else:
                        pass
                else:
                    pass

    def fbreg_train_info(self, function, offset, die, low_pc=None, high_pc=None):
        if len(function.frame_bases) == 0:
            pass
        elif len(function.frame_bases) == 1:
            frame_base = function.frame_bases[0]
            base_pointer = frame_base.base_register
            frame_offset = frame_base.offset + offset
            self.indirect_offset_train_info(function, base_pointer, frame_offset, die, self.get_die_type(die))
        else:
            for frame_base in function.frame_bases:
                base_pointer = frame_base.base_register
                frame_offset = frame_base.offset + offset
                frame_low_pc = frame_base.low_pc
                frame_high_pc = frame_base.high_pc
                if low_pc is None and high_pc is None:
                    self.indirect_offset_train_info(function, base_pointer, frame_offset, die, self.get_die_type(die), frame_low_pc, frame_high_pc)
                elif high_pc > frame_low_pc and low_pc < frame_high_pc:
                    self.indirect_offset_train_info(function, base_pointer, frame_offset, die, self.get_die_type(die), max(frame_low_pc, low_pc), min(frame_high_pc, high_pc))

    def indirect_offset_add_info(self, function, base_pointer, offset, die, low_pc, high_pc, ttype):
        key = (base_pointer, offset)
        # print(key)
        # traceback.print_stack(file=sys.stdout)
        if key in function.indirect_offsets:
            for indirect_offset in function.indirect_offsets[key].values():
                if low_pc is None and high_pc is None:
                    indirect_offset.train_info(die, ttype)
                else:
                    for pc in indirect_offset.pcs:
                        if pc >= low_pc and pc < high_pc:
                            indirect_offset.train_info(die, ttype)
                            break

    def reg_add_info(self, function, base_register, die, low_pc, high_pc):
        ttype = self.get_ttype_name(die)
        for reg in function.regs.values():
            if not isinstance(reg, GivReg) and reg.base_register == base_register:
                for pc in reg.pcs:
                    if (low_pc is None and high_pc is None) or low_pc <= pc < high_pc:
                        reg.train_info(die, ttype)
                        break
        if ttype == POINTER:
            pointer_ttype_die = self.get_pointer_ttype_die(die)
            pointer_ttype_name = self.get_ttype_name(pointer_ttype_die) if pointer_ttype_die is not None else VOID
            self.indirect_offset_train_info(function, base_register, 0, die, self.get_die_type(pointer_ttype_die), low_pc, high_pc, pointer_ttype_name)

    def indirect_offset_train_info(self, function, base_pointer, offset, die, die_type, low_pc=None, high_pc=None, ttype=None):
        if ttype is None:
            ttype = self.get_ttype_name(die)

        if die_type is None:
            self.indirect_offset_add_info(function, base_pointer, offset, die, low_pc, high_pc, ttype)
        elif die_type.tag == 'DW_TAG_array_type':
            byte_size = self.get_byte_size(die_type)
            upper_bound = self.get_array_upper_bound(die_type)
            if byte_size is not None and upper_bound is not None:
                if upper_bound * byte_size > MAX_UPPER_BOUND:
                    for key in function.indirect_offsets:
                        if key[0] == base_pointer and offset <= key[1] < upper_bound * byte_size + offset:
                            self.indirect_offset_add_info(function, key[0], key[1], die, low_pc, high_pc, ttype)
                else:
                    for i in range(0, upper_bound * byte_size):
                        off = offset + i
                        self.indirect_offset_add_info(function, base_pointer, off, die, low_pc, high_pc, ttype)
            else:
                self.indirect_offset_add_info(function, base_pointer, offset, die, low_pc, high_pc, ttype)
        elif die_type.tag == 'DW_TAG_union_type':
            byte_size = self.get_byte_size(die_type)
            if byte_size is not None:
                if byte_size > MAX_UPPER_BOUND:
                    for key in function.indirect_offsets:
                        if key[0] == base_pointer and offset <= key[1] < byte_size + offset:
                            self.indirect_offset_add_info(function, key[0], key[1], die, low_pc, high_pc, ttype)
                else:
                    for i in range(0, byte_size):
                        off = offset + i
                        self.indirect_offset_add_info(function, base_pointer, off, die, low_pc, high_pc, ttype)
            else:
                self.indirect_offset_add_info(function, base_pointer, offset, die, low_pc, high_pc, ttype)
        elif die_type.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type'):
            byte_size = self.get_byte_size(die_type)
            if byte_size is not None:
                if byte_size > MAX_UPPER_BOUND:
                    for key in function.indirect_offsets:
                        if key[0] == base_pointer and offset <= key[1] < byte_size + offset:
                            self.indirect_offset_add_info(function, key[0], key[1], die, low_pc, high_pc, ttype)
                else:
                    for i in range(0, byte_size):
                        off = offset + i
                        self.indirect_offset_add_info(function, base_pointer, off, die, low_pc, high_pc, ttype)
            else:
                self.indirect_offset_add_info(function, base_pointer, offset, die, low_pc, high_pc, ttype)

            for child in die_type.iter_children():
                child_offset_attr = die.attributes.get('DW_AT_data_member_location', None)
                if child_offset_attr is not None:
                    if child_offset_attr.form == 'DW_FORM_block1':
                        if child_offset_attr.value[0] == 0x23:
                            child_offset = utils.decode_uleb128(child_offset_attr[1:])
                            off = offset + child_offset
                            self.indirect_offset_train_info(function, base_pointer, off, die, die_type, low_pc, high_pc)
                        else:
                            pass
                    elif child_offset_attr.form == 'DW_FORM_data1':
                        child_offset = child_offset_attr.value
                        off = offset + child_offset
                        self.indirect_offset_train_info(function, base_pointer, off, die, die_type, low_pc, high_pc)
                    else:
                        pass
        else:
            byte_size = self.get_byte_size(die_type)
            if byte_size is not None:
                if byte_size > MAX_UPPER_BOUND:
                    for key in function.indirect_offsets:
                        if key[0] == base_pointer and offset <= key[1] < byte_size + offset:
                            self.indirect_offset_add_info(function, key[0], key[1], die, low_pc, high_pc, ttype)
                else:
                    for i in range(0, byte_size):
                        off = offset + i
                        self.indirect_offset_add_info(function, base_pointer, off, die, low_pc, high_pc, ttype)
            else:
                self.indirect_offset_add_info(function, base_pointer, offset, die, low_pc, high_pc, ttype)

    def direct_offset_train_info(self, offset, die, ttype=None):
        die_type = self.get_die_type(die)
        if ttype is None:
            ttype = self.get_ttype_name(die)

        if die_type is None:
            if offset in self.binary.direct_offsets:
                self.binary.direct_offsets[offset].train_info(die, ttype)
            else:
                pass
        elif die_type.tag == 'DW_TAG_array_type':
            byte_size = self.get_byte_size(die_type)
            upper_bound = self.get_array_upper_bound(die_type)
            if byte_size is not None and upper_bound is not None:
                if upper_bound * byte_size > MAX_UPPER_BOUND:
                    for off in self.binary.direct_offsets:
                        if offset <= off < upper_bound * byte_size:
                            self.binary.direct_offsets[off].train_info(die, ttype)
                else:
                    for i in range(0, upper_bound * byte_size):
                        off = offset + i
                        if off in self.binary.direct_offsets:
                            self.binary.direct_offsets[off].train_info(die, ttype)
            elif offset in self.binary.direct_offsets:
                self.binary.direct_offsets[offset].train_info(die, ttype)
            else:
                pass
        elif die_type.tag == 'DW_TAG_union_type':
            byte_size = self.get_byte_size(die_type)
            if byte_size is not None:
                if byte_size > MAX_UPPER_BOUND:
                    for off in self.binary.direct_offsets:
                        if offset <= off < offset + byte_size:
                            self.binary.direct_offsets[off].train_info(die, ttype)
                else:
                    for i in range(0, byte_size):
                        off = offset + i
                        if off in self.binary.direct_offsets:
                            self.binary.direct_offsets[off].train_info(die, ttype)
            elif offset in self.binary.direct_offsets:
                self.binary.direct_offsets[offset].train_info(die, ttype)
            else:
                pass
        elif die_type.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type'):
            byte_size = self.get_byte_size(die_type)
            if byte_size is not None:
                if byte_size > MAX_UPPER_BOUND:
                    for off in self.binary.direct_offsets:
                        if offset <= off < offset + byte_size:
                            self.binary.direct_offsets[off].train_info(die, ttype)
                else:
                    for i in range(0, byte_size):
                        off = offset + i
                        if off in self.binary.direct_offsets:
                            self.binary.direct_offsets[off].train_info(die, ttype)
            elif offset in self.binary.direct_offsets:
                self.binary.direct_offsets[offset].train_info(die, ttype)
            else:
                pass

            for child in die_type.iter_children():
                child_offset_attr = die.attributes.get('DW_AT_data_member_location', None)
                if child_offset_attr is not None:
                    if child_offset_attr.form == 'DW_FORM_block1':
                        if child_offset_attr.value[0] == 0x23:
                            child_offset = utils.decode_uleb128(child_offset_attr[1:])
                            off = offset + child_offset
                            self.direct_offset_train_info(off, die, ttype)
                        else:
                            pass
                    elif child_offset_attr.form == 'DW_FORM_data1':
                        child_offset = child_offset_attr.value
                        off = offset + child_offset
                        self.direct_offset_train_info(off, die, ttype)
                    else:
                        pass
        elif offset in self.binary.direct_offsets:
            byte_size = self.get_byte_size(die_type)
            if byte_size is not None:
                if byte_size > MAX_UPPER_BOUND:
                    for off in self.binary.direct_offsets:
                        if offset <= off < byte_size + offset:
                            self.binary.direct_offsets[off].train_info(die, ttype)
                else:
                    for i in range(0, byte_size):
                        off = offset + i
                        if off in self.binary.direct_offsets:
                            self.binary.direct_offsets[off].train_info(die, ttype)
            else:
                self.binary.direct_offsets[offset].train_info(die, ttype)
        else:
            pass

    def location_list_train_info(self, function, loc_offset, die, cu_low_pc):
        location_list = self.location_lists.get_location_list_at_offset(loc_offset)
        for entry in location_list:
            if isinstance(entry, LocationEntry):
                low_pc = entry.begin_offset + cu_low_pc
                high_pc = entry.end_offset + cu_low_pc
                loc = entry.loc_expr
                if len(loc) > 0:
                    # print(entry)
                    self.loc_train_info(function, loc, die, low_pc, high_pc)
                else:
                    pass
            else:
                pass

    def loc_train_info(self, function, loc, die, low_pc=None, high_pc=None):
        if loc[0] == ENUM_DW_FORM_exprloc['DW_OP_fbreg']:
            self.fbreg_train_info(function, decode_sleb128(loc[1:]), die, low_pc, high_pc)
        elif ENUM_DW_FORM_exprloc['DW_OP_breg0'] <= loc[0] <= ENUM_DW_FORM_exprloc['DW_OP_breg31'] \
                and (loc[0] - ENUM_DW_FORM_exprloc['DW_OP_breg0']) in self.binary.config.REG_MAPPING:
            base_pointer = self.binary.config.REG_MAPPING[loc[0] - ENUM_DW_FORM_exprloc['DW_OP_breg0']]
            offset = decode_sleb128(loc[1:])
            self.indirect_offset_train_info(function, base_pointer, offset, die, self.get_die_type(die))
        elif loc[0] == ENUM_DW_FORM_exprloc['DW_OP_addr']:
            offset = decode_address(loc[1:], self.binary)
            self.direct_offset_train_info(offset, die)
        elif ENUM_DW_FORM_exprloc['DW_OP_reg0'] <= loc[0] <= ENUM_DW_FORM_exprloc['DW_OP_reg31'] \
                and (loc[0] - ENUM_DW_FORM_exprloc['DW_OP_reg0']) in self.binary.config.REG_MAPPING:
            base_register = self.binary.config.REG_MAPPING[loc[0] - ENUM_DW_FORM_exprloc['DW_OP_reg0']]
            self.reg_add_info(function, base_register, die, low_pc, high_pc)
        else:
            pass
