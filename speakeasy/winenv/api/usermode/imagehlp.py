import struct

from .. import api


class Imagehlp(api.ApiHandler):
    """
    Emulates functions from imagehlp.dll
    """

    name = "imagehlp"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("CheckSumMappedFile", argc=4)
    def CheckSumMappedFile(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PIMAGE_NT_HEADERS CheckSumMappedFile(
          PVOID  BaseAddress,
          DWORD  FileLength,
          PDWORD HeaderSum,
          PDWORD CheckSum
        );
        """
        base, length, header_sum, check_sum = argv
        data = self.mem_read(base, length) + b"\x00" * (length & 1)
        calc = sum(struct.unpack(f"<{len(data) // 2}H", data))
        while calc >> 16:
            calc = (calc & 0xFFFF) + (calc >> 16)

        if self.mem_read(base, 2) != b"MZ":
            return 0
        nt = base + struct.unpack("<I", self.mem_read(base + 0x3C, 4))[0]
        if self.mem_read(nt, 4) != b"PE\x00\x00":
            return 0
        stored = struct.unpack("<I", self.mem_read(nt + 24 + 64, 4))[0]
        self.mem_write(header_sum, stored.to_bytes(4, "little"))

        # Remove the stored checksum from the one's complement sum, as Windows does
        for word in (stored & 0xFFFF, stored >> 16):
            if calc & 0xFFFF >= word:
                calc -= word
            else:
                calc = ((calc - word) & 0xFFFF) - 1
        self.mem_write(check_sum, ((calc + length) & 0xFFFFFFFF).to_bytes(4, "little"))
        return nt
