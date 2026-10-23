from .. import api

OK = 0
GENERIC_ERROR = 1
INVALID_PARAMETER = 2


class Gdiplus(api.ApiHandler):
    """
    Implements the GDI+ flat API from gdiplus.dll. Startup and memory functions
    work. Image decoding fails, because the emulator has no image codecs.
    """

    name = "gdiplus"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("GdiplusStartup", argc=3)
    def GdiplusStartup(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        Status GdiplusStartup(
            ULONG_PTR *token,
            const GdiplusStartupInput *input,
            GdiplusStartupOutput *output
        );
        """
        token, startup_input, output = argv
        if not token or not startup_input:
            return INVALID_PARAMETER
        self.mem_write(token, (1).to_bytes(emu.get_ptr_size(), "little"))
        if output:
            self.mem_write(output, b"\x00" * 2 * emu.get_ptr_size())
        return OK

    @apihook("GdiplusShutdown", argc=1)
    def GdiplusShutdown(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """void GdiplusShutdown(ULONG_PTR token);"""
        return None

    @apihook("GdipAlloc", argc=1)
    def GdipAlloc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """void *GdipAlloc(size_t size);"""
        (size,) = argv
        return self.heap_alloc(size, heap="HeapAlloc")

    @apihook("GdipFree", argc=1)
    def GdipFree(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """void GdipFree(void *ptr);"""
        (ptr,) = argv
        if ptr:
            self.mem_free(ptr)
        return None

    def fail_image(self, emu, out):
        if out:
            self.mem_write(out, b"\x00" * emu.get_ptr_size())
        return GENERIC_ERROR

    @apihook("GdipCreateBitmapFromStream", argc=2)
    def GdipCreateBitmapFromStream(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Status GdipCreateBitmapFromStream(IStream *stream, GpBitmap **bitmap);"""
        return self.fail_image(emu, argv[1])

    @apihook("GdipCreateBitmapFromFile", argc=2)
    def GdipCreateBitmapFromFile(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Status GdipCreateBitmapFromFile(const WCHAR *filename, GpBitmap **bitmap);"""
        return self.fail_image(emu, argv[1])

    @apihook("GdipLoadImageFromStream", argc=2)
    def GdipLoadImageFromStream(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Status GdipLoadImageFromStream(IStream *stream, GpImage **image);"""
        return self.fail_image(emu, argv[1])

    @apihook("GdipLoadImageFromFile", argc=2)
    def GdipLoadImageFromFile(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Status GdipLoadImageFromFile(const WCHAR *filename, GpImage **image);"""
        return self.fail_image(emu, argv[1])

    @apihook("GdipCreateBitmapFromStreamICM", argc=2)
    def GdipCreateBitmapFromStreamICM(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Status GdipCreateBitmapFromStreamICM(IStream *stream, GpBitmap **bitmap);"""
        return self.fail_image(emu, argv[1])

    @apihook("GdipCreateBitmapFromFileICM", argc=2)
    def GdipCreateBitmapFromFileICM(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Status GdipCreateBitmapFromFileICM(const WCHAR *filename, GpBitmap **bitmap);"""
        return self.fail_image(emu, argv[1])

    @apihook("GdipLoadImageFromStreamICM", argc=2)
    def GdipLoadImageFromStreamICM(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Status GdipLoadImageFromStreamICM(IStream *stream, GpImage **image);"""
        return self.fail_image(emu, argv[1])

    @apihook("GdipLoadImageFromFileICM", argc=2)
    def GdipLoadImageFromFileICM(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Status GdipLoadImageFromFileICM(const WCHAR *filename, GpImage **image);"""
        return self.fail_image(emu, argv[1])

    @apihook("GdipDisposeImage", argc=1)
    def GdipDisposeImage(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Status GdipDisposeImage(GpImage *image);"""
        return OK if argv[0] else INVALID_PARAMETER
