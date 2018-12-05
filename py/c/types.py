from common.constants import POINTER, ENUM, ARRAY, UNION, STRUCT
from common.constants import VOID, SHORT, UNSIGNED_SHORT, CHAR, UNSIGNED_CHAR
from common.constants import LONG_LONG, UNSIGNED_LONG_LONG, LONG
from common.constants import UNSIGNED_LONG, INT, UNSIGNED_INT, BOOL
from common.constants import ENUM_ABBREV_CODE, ENUM_DW_TAG, ENUM_DW_CHILDREN
from common.constants import ENUM_DW_AT, ENUM_DW_FORM, ENUM_DW_ATE


def type_factory(t, offset, binary):
    if t == POINTER:
        return PointerType(offset=offset, binary=binary)
    elif t == ENUM:
        return EnumType(offset=offset, binary=binary)
    elif t == ARRAY:
        return ArrayType(offset=offset, binary=binary)
    elif t == UNION:
        return UnionType(offset=offset, binary=binary)
    elif t == STRUCT:
        return StructType(offset=offset, binary=binary)
    elif t == SHORT:
        return ShortType(offset=offset, binary=binary)
    elif t == UNSIGNED_SHORT:
        return UnsignedShortType(offset=offset, binary=binary)
    elif t == CHAR:
        return CharType(offset=offset, binary=binary)
    elif t == UNSIGNED_CHAR:
        return UnsignedCharType(offset=offset, binary=binary)
    elif t == LONG_LONG:
        return LongLongType(offset=offset, binary=binary)
    elif t == UNSIGNED_LONG_LONG:
        return UnsignedLongLongType(offset=offset, binary=binary)
    elif t == LONG:
        return LongType(offset=offset, binary=binary)
    elif t == UNSIGNED_LONG:
        return UnsignedLongType(offset=offset, binary=binary)
    elif t == INT:
        return IntType(offset=offset, binary=binary)
    elif t == UNSIGNED_INT:
        return UnsignedIntType(offset=offset, binary=binary)
    elif t == BOOL:
        return BoolType(offset=offset, binary=binary)
    else:
        return IntType(offset=offset, binary=binary)


class Types:
    def __init__(self, *args, **kwargs):
        self.offset = kwargs['offset']
        self.binary = kwargs['binary']
        self.content = bytearray()
        self.types = dict()

    def add_type(self, t):
        if t not in self.types:
            tt = type_factory(t, self.offset + len(self.content) + 4, self.binary)
            self.types[t] = tt
            self.content += tt.debug_info()

    def get_type(self, t):
        return self.types[t] if t in self.types else None

    def get_offset(self, t):
        if t not in self.types:
            self.add_type(t)
        return self.types[t].offset

    def debug_abbrev(self):
        bs = bytearray()

        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(ENUM_DW_TAG['DW_TAG_base_type'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_no'])
        bs.append(ENUM_DW_AT['DW_AT_byte_size'])
        bs.append(ENUM_DW_FORM['DW_FORM_data1'])
        bs.append(ENUM_DW_AT['DW_AT_encoding'])
        bs.append(ENUM_DW_FORM['DW_FORM_data1'])
        bs.append(ENUM_DW_AT['DW_AT_name'])
        bs.append(ENUM_DW_FORM['DW_FORM_string'])
        bs.append(0x00)
        bs.append(0x00)

        bs.append(ENUM_ABBREV_CODE['POINTER_TYPE'])
        bs.append(ENUM_DW_TAG['DW_TAG_pointer_type'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_no'])
        bs.append(ENUM_DW_AT['DW_AT_byte_size'])
        bs.append(ENUM_DW_FORM['DW_FORM_data1'])
        bs.append(0x00)
        bs.append(0x00)

        bs.append(ENUM_ABBREV_CODE['ENUM_TYPE'])
        bs.append(ENUM_DW_TAG['DW_TAG_enumeration_type'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_no'])
        bs.append(ENUM_DW_AT['DW_AT_name'])
        bs.append(ENUM_DW_FORM['DW_FORM_string'])
        bs.append(ENUM_DW_AT['DW_AT_byte_size'])
        bs.append(ENUM_DW_FORM['DW_FORM_data1'])
        bs.append(0x00)
        bs.append(0x00)

        bs.append(ENUM_ABBREV_CODE['ARRAY_TYPE'])
        bs.append(ENUM_DW_TAG['DW_TAG_array_type'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_no'])
        bs.append(0x00)
        bs.append(0x00)

        bs.append(ENUM_ABBREV_CODE['UNION_TYPE'])
        bs.append(ENUM_DW_TAG['DW_TAG_union_type'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_no'])
        bs.append(ENUM_DW_AT['DW_AT_name'])
        bs.append(ENUM_DW_FORM['DW_FORM_string'])
        bs.append(ENUM_DW_AT['DW_AT_byte_size'])
        bs.append(ENUM_DW_FORM['DW_FORM_data1'])
        bs.append(0x00)
        bs.append(0x00)

        bs.append(ENUM_ABBREV_CODE['STRUCT_TYPE'])
        bs.append(ENUM_DW_TAG['DW_TAG_structure_type'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_no'])
        bs.append(ENUM_DW_AT['DW_AT_byte_size'])
        bs.append(ENUM_DW_FORM['DW_FORM_data1'])
        bs.append(ENUM_DW_AT['DW_AT_name'])
        bs.append(ENUM_DW_FORM['DW_FORM_string'])
        bs.append(0x00)
        bs.append(0x00)

        return bs


class Type:
    def __init__(self, *args, **kwargs):
        self.offset = kwargs['offset']
        self.binary = kwargs['binary']


class PointerType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = POINTER
        self.byte_size = self.binary.config.ADDRESS_BYTE_SIZE

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['POINTER_TYPE'])
        bs.append(self.byte_size)
        return bs


class EnumType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ENUM
        self.byte_size = 4

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['ENUM_TYPE'])
        bs.extend(map(ord, 'ENUM'))
        bs.append(0x00)
        bs.append(self.byte_size)
        return bs


class ArrayType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ARRAY

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['ARRAY_TYPE'])
        return bs


class UnionType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = UNION
        self.byte_size = self.binary.config.ADDRESS_BYTE_SIZE

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['UNION_TYPE'])
        bs.extend(map(ord, 'UNION'))
        bs.append(0x00)
        bs.append(self.byte_size)
        return bs


class StructType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = STRUCT
        self.byte_size = self.binary.config.ADDRESS_BYTE_SIZE

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['STRUCT_TYPE'])
        bs.append(self.byte_size)
        bs.extend(map(ord, 'STRUCT'))
        bs.append(0x0)
        return bs


class ShortType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = SHORT
        self.byte_size = 2

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(self.byte_size)
        bs.append(ENUM_DW_ATE['DW_ATE_signed'])
        bs.extend(map(ord, self.name))
        bs.append(0x0)
        return bs


class UnsignedShortType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = UNSIGNED_SHORT
        self.byte_size = 2

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(self.byte_size)
        bs.append(ENUM_DW_ATE['DW_ATE_unsigned'])
        bs.extend(map(ord, self.name))
        bs.append(0x0)
        return bs


class CharType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = CHAR
        self.byte_size = 1

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(self.byte_size)
        bs.append(ENUM_DW_ATE['DW_ATE_signed'])
        bs.extend(map(ord, self.name))
        bs.append(0x0)
        return bs


class UnsignedCharType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = UNSIGNED_CHAR
        self.byte_size = 1

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(self.byte_size)
        bs.append(ENUM_DW_ATE['DW_ATE_unsigned'])
        bs.extend(map(ord, self.name))
        bs.append(0x0)
        return bs


class LongLongType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = LONG_LONG
        self.byte_size = 8

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(self.byte_size)
        bs.append(ENUM_DW_ATE['DW_ATE_signed'])
        bs.extend(map(ord, self.name))
        bs.append(0x0)
        return bs


class UnsignedLongLongType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = UNSIGNED_LONG_LONG
        self.byte_size = 8

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(self.byte_size)
        bs.append(ENUM_DW_ATE['DW_ATE_unsigned'])
        bs.extend(map(ord, self.name))
        bs.append(0x0)
        return bs


class LongType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = LONG
        self.byte_size = 8 if self.binary.config.MACHINE_ARCH == 'x64' else 4

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(self.byte_size)
        bs.append(ENUM_DW_ATE['DW_ATE_signed'])
        bs.extend(map(ord, self.name))
        bs.append(0x0)
        return bs


class UnsignedLongType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = UNSIGNED_LONG
        self.byte_size = 8 if self.binary.config.MACHINE_ARCH == 'x64' else 4

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(self.byte_size)
        bs.append(ENUM_DW_ATE['DW_ATE_unsigned'])
        bs.extend(map(ord, self.name))
        bs.append(0x0)
        return bs


class IntType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = INT
        self.byte_size = 4

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(self.byte_size)
        bs.append(ENUM_DW_ATE['DW_ATE_signed'])
        bs.extend(map(ord, self.name))
        bs.append(0x0)
        return bs


class UnsignedIntType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = UNSIGNED_INT
        self.byte_size = 4

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(self.byte_size)
        bs.append(ENUM_DW_ATE['DW_ATE_unsigned'])
        bs.extend(map(ord, self.name))
        bs.append(0x0)
        return bs


class BoolType(Type):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = BOOL
        self.byte_size = 1

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['BASE_TYPE_WITH_ENCODING'])
        bs.append(self.byte_size)
        bs.append(ENUM_DW_ATE['DW_ATE_boolean'])
        bs.extend(map(ord, self.name))
        bs.append(0x0)
        return bs
