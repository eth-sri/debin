class FrameBase:
    def __init__(self, *args, **kwargs):
        self.low_pc = kwargs['low_pc']
        self.high_pc = kwargs['high_pc']
        self.base_register = kwargs['base_register']
        self.offset = kwargs['offset']

    def __repr__(self):
        return '{} {} {} {}'.format(self.base_register, self.offset, format(self.low_pc, '02x'), format(self.high_pc, '02x'))
