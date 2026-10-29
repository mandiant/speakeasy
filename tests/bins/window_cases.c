// Window cases for speakeasy's user32 handlers, on x86. main returns a bitmask with one
// bit per case that behaves as it does on Windows (0x3F: all).
//
// No user input arrives in speakeasy. The dialog that does not call EndDialog during
// WM_INITDIALOG stays open on Windows until the user closes it, and then gives IDCANCEL.
//
// Built without a CRT or SDK; build_programs.sh in this directory builds it.

typedef void *HWND;
typedef void *HINSTANCE;
typedef unsigned int UINT;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef int INT_PTR;
typedef INT_PTR(__stdcall *DLGPROC)(HWND, UINT, WPARAM, LPARAM);
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef int(__stdcall *WNDENUMPROC)(HWND, LPARAM);

typedef struct {
    UINT cbSize, style;
    WNDPROC lpfnWndProc;
    int cbClsExtra, cbWndExtra;
    HINSTANCE hInstance;
    void *hIcon, *hCursor, *hbrBackground;
    const char *lpszMenuName, *lpszClassName;
    void *hIconSm;
} WNDCLASSEXA;

typedef struct {
    void *lpCreateParams;
    HINSTANCE hInstance;
    void *hMenu;
    HWND hwndParent;
    int cy, cx, y, x;
    long style;
    const char *lpszName, *lpszClass;
    unsigned long dwExStyle;
} CREATESTRUCTA;

__declspec(dllimport) INT_PTR __stdcall DialogBoxParamA(HINSTANCE, const char *, HWND, DLGPROC, LPARAM);
__declspec(dllimport) int __stdcall EndDialog(HWND, INT_PTR);
__declspec(dllimport) int __stdcall EnumWindows(WNDENUMPROC, LPARAM);
__declspec(dllimport) HWND __stdcall CreateWindowExA(unsigned long, const char *, const char *, unsigned long, int, int,
                                                     int, int, HWND, void *, HINSTANCE, void *);
__declspec(dllimport) unsigned short __stdcall RegisterClassExA(const WNDCLASSEXA *);
__declspec(dllimport) LRESULT __stdcall DefWindowProcA(HWND, UINT, WPARAM, LPARAM);

extern char __ImageBase;
#define INSTANCE ((HINSTANCE)&__ImageBase)

#define DIALOG ((const char *)101)
#define IDCANCEL 2
#define WM_CREATE 0x1
#define WM_NCCREATE 0x81
#define WM_INITDIALOG 0x110
#define WM_COMMAND 0x111
#define WS_POPUP 0x80000000
#define WS_CHILD 0x40000000
#define WS_EX_TOOLWINDOW 0x80
#define INIT_PARAM 0x55

static LPARAM init_lparam;

static INT_PTR __stdcall ending_dialog(HWND dialog, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message != WM_INITDIALOG)
        return 0;
    init_lparam = lparam;
    EndDialog(dialog, 0x1234);
    return 1;
}

static INT_PTR __stdcall waiting_dialog(HWND dialog, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_INITDIALOG) {
        init_lparam = lparam;
        return 1;
    }
    if (message == WM_COMMAND && (wparam & 0xFFFF) == IDCANCEL) {
        EndDialog(dialog, IDCANCEL);
        return 1;
    }
    return 0;
}

// DialogBoxParam sends WM_INITDIALOG with dwInitParam, and returns the EndDialog result
__declspec(noinline) static int dialog_case(DLGPROC procedure, INT_PTR expected) {
    init_lparam = 0;
    return DialogBoxParamA(INSTANCE, DIALOG, 0, procedure, INIT_PARAM) == expected && init_lparam == INIT_PARAM;
}

static HWND popup, child;
static int continue_enumeration, enum_calls, saw_popup, saw_child, other_lparam;

static int __stdcall enum_window(HWND window, LPARAM lparam) {
    enum_calls++;
    saw_popup |= window == popup;
    saw_child |= window == child;
    other_lparam |= lparam != INIT_PARAM;
    return continue_enumeration;
}

__declspec(noinline) static int enum_windows(int continue_after_each) {
    continue_enumeration = continue_after_each;
    enum_calls = saw_popup = saw_child = other_lparam = 0;
    return EnumWindows(enum_window, INIT_PARAM);
}

// EnumWindows calls the callback for each top-level window, and stops with 0 when the callback returns FALSE
__declspec(noinline) static int enum_windows_cases(void) {
    int stopped, completed;
    popup = CreateWindowExA(0, "STATIC", 0, WS_POPUP, 0, 0, 0, 0, 0, 0, INSTANCE, 0);
    child = CreateWindowExA(0, "STATIC", 0, WS_CHILD, 0, 0, 0, 0, popup, 0, INSTANCE, 0);
    stopped = enum_windows(0) == 0 && enum_calls == 1 && !other_lparam;
    completed = enum_windows(1) != 0 && saw_popup && !saw_child && !other_lparam;
    return popup && child ? stopped | completed << 1 : 0;
}

static UINT fail_at;
static UINT messages[4];
static int message_count, create_struct_ok;

static int equal(const char *a, const char *b) {
    while (*a && *a == *b)
        a++, b++;
    return *a == *b;
}

static int has_create_arguments(const CREATESTRUCTA *cs) {
    return cs->lpCreateParams == (void *)0x1234 && cs->hInstance == INSTANCE && !cs->hMenu && !cs->hwndParent &&
           cs->x == 10 && cs->y == 20 && cs->cx == 30 && cs->cy == 40 && cs->style == (long)WS_POPUP &&
           cs->dwExStyle == WS_EX_TOOLWINDOW && equal(cs->lpszName, "title") && equal(cs->lpszClass, "window_cases");
}

// returns FALSE for WM_NCCREATE or -1 for WM_CREATE, as fail_at selects
static LRESULT __stdcall rejecting_window(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message != WM_NCCREATE && message != WM_CREATE)
        return DefWindowProcA(window, message, wparam, lparam);
    if (message_count < 4)
        messages[message_count] = message;
    message_count++;
    create_struct_ok &= has_create_arguments((const CREATESTRUCTA *)lparam);
    if (message == WM_NCCREATE)
        return fail_at != WM_NCCREATE;
    return fail_at == WM_CREATE ? -1 : 0;
}

static WNDCLASSEXA window_class = {sizeof(WNDCLASSEXA), 0, rejecting_window, 0, 0, INSTANCE, 0, 0, 0, 0, "window_cases", 0};

// CreateWindowEx sends WM_NCCREATE and WM_CREATE with a CREATESTRUCT of its arguments,
// and fails when the window procedure rejects either
__declspec(noinline) static int create_window_case(UINT reject, int expected_count) {
    HWND window;
    fail_at = reject;
    message_count = 0;
    create_struct_ok = 1;
    window = CreateWindowExA(WS_EX_TOOLWINDOW, "window_cases", "title", WS_POPUP, 10, 20, 30, 40, 0, 0, INSTANCE,
                             (void *)0x1234);
    return !window && message_count == expected_count && messages[0] == WM_NCCREATE &&
           (expected_count == 1 || messages[1] == WM_CREATE) && create_struct_ok;
}

int main(void) {
    int result = dialog_case(ending_dialog, 0x1234);
    result |= dialog_case(waiting_dialog, IDCANCEL) << 1;
    result |= enum_windows_cases() << 2;
    if (RegisterClassExA(&window_class)) {
        result |= create_window_case(WM_NCCREATE, 1) << 4;
        result |= create_window_case(WM_CREATE, 2) << 5;
    }
    return result;
}
