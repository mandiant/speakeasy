// AES-GCM cases for speakeasy's bcrypt handlers, on x64 and x86. main encrypts 64 bytes
// with a 256-bit key, writes the cipher text and the 16-byte tag to c:\gcm.bin, and
// returns a bitmask with one bit per case that behaves as it does on Windows (0x7F: all).
//
// key: bytes 0x00 to 0x1F, nonce: 12 bytes of 0x07, authenticated data: "UK01",
// plain text: bytes 0x40 to 0x7F.
//
// Built without a CRT or SDK; build_programs.sh in this directory builds it.

typedef unsigned short wchar_t;
typedef long NTSTATUS;
typedef void *HANDLE;
typedef unsigned long ULONG;
typedef unsigned char UCHAR;

typedef struct {
    ULONG cbSize, dwInfoVersion;
    UCHAR *pbNonce;
    ULONG cbNonce;
    UCHAR *pbAuthData;
    ULONG cbAuthData;
    UCHAR *pbTag;
    ULONG cbTag;
    UCHAR *pbMacContext;
    ULONG cbMacContext, cbAAD;
    unsigned long long cbData;
    ULONG dwFlags;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;

typedef struct {
    ULONG dwMinLength, dwMaxLength, dwIncrement;
} BCRYPT_AUTH_TAG_LENGTHS_STRUCT;

__declspec(dllimport) NTSTATUS __stdcall BCryptOpenAlgorithmProvider(HANDLE *, const wchar_t *, const wchar_t *, ULONG);
__declspec(dllimport) NTSTATUS __stdcall BCryptSetProperty(HANDLE, const wchar_t *, void *, ULONG, ULONG);
__declspec(dllimport) NTSTATUS __stdcall BCryptGenerateSymmetricKey(HANDLE, HANDLE *, UCHAR *, ULONG, UCHAR *, ULONG,
                                                                    ULONG);
__declspec(dllimport) NTSTATUS __stdcall BCryptGetProperty(HANDLE, const wchar_t *, void *, ULONG, ULONG *, ULONG);
__declspec(dllimport) NTSTATUS __stdcall BCryptEncrypt(HANDLE, UCHAR *, ULONG, void *, UCHAR *, ULONG, UCHAR *, ULONG,
                                                       ULONG *, ULONG);
__declspec(dllimport) NTSTATUS __stdcall BCryptDecrypt(HANDLE, UCHAR *, ULONG, void *, UCHAR *, ULONG, UCHAR *, ULONG,
                                                       ULONG *, ULONG);
__declspec(dllimport) NTSTATUS __stdcall BCryptDestroyKey(HANDLE);
__declspec(dllimport) HANDLE __stdcall CreateFileA(const char *, ULONG, ULONG, void *, ULONG, ULONG, HANDLE);
__declspec(dllimport) int __stdcall WriteFile(HANDLE, const void *, ULONG, ULONG *, void *);
__declspec(dllimport) int __stdcall CloseHandle(HANDLE);

#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002)
#define GENERIC_WRITE 0x40000000
#define CREATE_ALWAYS 2

static wchar_t chaining_mode_gcm[] = L"ChainingModeGCM";
static UCHAR nonce[12] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
static UCHAR auth_data[4] = {'U', 'K', '0', '1'};
static UCHAR key_bytes[32], plain[64], decrypted[64];
// the cipher text, then the tag
static UCHAR output[80];
static BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
static BCRYPT_AUTH_TAG_LENGTHS_STRUCT tag_lengths;

static int is_plain(const UCHAR *data) {
    int i;
    for (i = 0; i < 64; i++)
        if (data[i] != plain[i])
            return 0;
    return 1;
}

static void write_output(void) {
    ULONG written;
    HANDLE file = CreateFileA("c:\\gcm.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    WriteFile(file, output, sizeof(output), &written, 0);
    CloseHandle(file);
}

int main(void) {
    HANDLE algorithm, key;
    ULONG size, block_length;
    int i, result;

    for (i = 0; i < 32; i++)
        key_bytes[i] = (UCHAR)i;
    for (i = 0; i < 64; i++)
        plain[i] = (UCHAR)(0x40 + i);
    if (BCryptOpenAlgorithmProvider(&algorithm, L"AES", 0, 0) ||
        BCryptSetProperty(algorithm, L"ChainingMode", chaining_mode_gcm, sizeof(chaining_mode_gcm), 0) ||
        BCryptGenerateSymmetricKey(algorithm, &key, 0, 0, key_bytes, sizeof(key_bytes), 0))
        return 0;

    result = !BCryptGetProperty(key, L"AuthTagLength", &tag_lengths, sizeof(tag_lengths), &size, 0) &&
             size == sizeof(tag_lengths) && tag_lengths.dwMinLength == 12 && tag_lengths.dwMaxLength == 16 &&
             tag_lengths.dwIncrement == 1;
    result |= (!BCryptGetProperty(key, L"BlockLength", &block_length, sizeof(block_length), &size, 0) &&
               size == sizeof(block_length) && block_length == 16)
              << 1;

    info.cbSize = sizeof(info);
    info.dwInfoVersion = 1;
    info.pbNonce = nonce;
    info.cbNonce = sizeof(nonce);
    info.pbAuthData = auth_data;
    info.cbAuthData = sizeof(auth_data);
    info.pbTag = output + 64;
    info.cbTag = 16;

    result |= (!BCryptEncrypt(key, plain, 64, &info, 0, 0, 0, 0, &size, 0) && size == 64) << 2;
    result |= (!BCryptEncrypt(key, plain, 64, &info, 0, 0, output, 64, &size, 0) && size == 64) << 3;
    write_output();
    result |= (!BCryptDecrypt(key, output, 64, &info, 0, 0, decrypted, 64, &size, 0) && is_plain(decrypted)) << 4;
    output[64] ^= 1;
    result |= (BCryptDecrypt(key, output, 64, &info, 0, 0, decrypted, 64, &size, 0) == STATUS_AUTH_TAG_MISMATCH) << 5;
    result |= !BCryptDestroyKey(key) << 6;
    return result;
}
