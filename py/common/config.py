class Config:

    def __init__(self):
        self.TRAIN = 0
        self.TEST = 1

        self.GIV = 0
        self.INF = 1

        self.INDIRECT_OFFSET_WITH_INDEX = False
        self.TWO_PASS = False
        self.USE_SUPPORT = False
        self.UNK_GIV = False

        self.MODE = self.TRAIN
        self.BINARY_PATH = ''
        self.BINARY_NAME = ''
        self.OUTPUT_BINARY_PATH = ''
        self.DEBUG_INFO_PATH = ''
        self.GRAPH_PATH = ''
        self.BAP_FILE_PATH = ''
        self.FP_MODEL_PATH = ''
        self.STAT_PATH = ''
        self.PREDICTEDS_PATH = ''
        self.CORRECTS_PATH = ''
        self.ERRORS_PATH = ''
        self.DEBUG_PATH = ''
        self.PROGRESS_PATH = ''
        self.MODIFY_ELF_LIB_PATH = ''
        self.BYTEWEIGHT_SIGS_PATH = ''
        self.N2P_SERVER_URL = ''

        self.REG_DICT = None
        self.REG_SUPPORT = None
        self.REG_MODEL = None
        self.OFF_DICT = None
        self.OFF_SUPPORT = None
        self.OFF_MODEL = None

        self.MACHINE_ARCH = ''
        self.REG_MAPPING = None
        self.SYSCALL_TABLE = None
        self.ADDRESS_BYTE_SIZE = 4
        self.HIGH_PC = 0x7fffffff
