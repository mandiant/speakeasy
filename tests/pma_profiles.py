import shutil
from pathlib import Path
from typing import Any

from tests.pma_harness import TESTS_DIR, CaseRuntime

REG_PATH_1102 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"


def ensure_user_module(cfg: dict[str, Any], name: str, base_addr: str, path: str) -> None:
    user_modules = cfg.setdefault("modules", {}).setdefault("user_modules", [])
    if any((module.get("name") or "").lower() == name.lower() for module in user_modules):
        return
    user_modules.append({"name": name, "base_addr": base_addr, "path": path})


def set_main_command_line(cfg: dict[str, Any], command_line: str) -> None:
    cfg["command_line"] = command_line
    for process in cfg.get("processes", []):
        if process.get("is_main_exe"):
            process["command_line"] = command_line
            break


def profile_pma_0102(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    cfg["timeout"] = 2
    cfg["max_api_count"] = 250
    return CaseRuntime()


def profile_pma_0104(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    cfg["timeout"] = 2
    cfg["max_api_count"] = 250
    ensure_user_module(cfg, "psapi", "0x71000000", "C:\\Windows\\system32\\psapi.dll")
    return CaseRuntime()


def ensure_pma_0304_registry(cfg: dict[str, Any]) -> None:
    key = {
        "path": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft \\XPS",
        "values": [{"name": "Configuration", "type": "REG_SZ", "data": "1"}],
    }
    keys = cfg.setdefault("registry", {}).setdefault("keys", [])
    if not any((item.get("path") or "").lower() == key["path"].lower() for item in keys):
        keys.append(key)


def profile_pma_0304_probe(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    set_main_command_line(cfg, "svchost.exe")
    ensure_pma_0304_registry(cfg)
    return CaseRuntime()


def profile_pma_0304_in(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    set_main_command_line(cfg, "svchost.exe -in abcd")
    ensure_pma_0304_registry(cfg)
    return CaseRuntime()


def profile_pma_0304_re(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    set_main_command_line(cfg, "svchost.exe -re abcd")
    ensure_pma_0304_registry(cfg)
    return CaseRuntime()


def profile_pma_0304_cc(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    set_main_command_line(cfg, "svchost.exe -cc abcd")
    ensure_pma_0304_registry(cfg)
    return CaseRuntime()


def profile_pma_1102_deep(cfg: dict[str, Any], tmp_path: Path) -> CaseRuntime:
    ini_path = tmp_path / "Lab11-02.ini"
    plain = b"lab11-02@example.com\r\n"
    ini_path.write_bytes(bytes(byte ^ 0x21 for byte in plain))

    cfg.setdefault("filesystem", {}).setdefault("files", []).insert(
        0,
        {
            "mode": "full_path",
            "emu_path": "C:\\Windows\\system32\\Lab11-02.ini",
            "path": str(ini_path),
        },
    )

    keys = cfg.setdefault("registry", {}).setdefault("keys", [])
    if not any((key.get("path") or "").lower() == REG_PATH_1102.lower() for key in keys):
        keys.append({"path": REG_PATH_1102, "values": []})

    for process in cfg.get("processes", []):
        if process.get("is_main_exe"):
            process["name"] = "outlook"
            process["path"] = "C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE"
            process["command_line"] = "OUTLOOK.EXE"
            break

    return CaseRuntime()


def profile_pma_1103_dll(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    cfg["timeout"] = 20
    cfg["max_api_count"] = 500
    return CaseRuntime()


def profile_pma_1103_exe_missing_source(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    cfg.setdefault("filesystem", {}).setdefault("files", [])
    cfg["filesystem"]["files"] = [
        file
        for file in cfg["filesystem"]["files"]
        if not (
            file.get("mode") == "full_path"
            and (file.get("emu_path") or "").lower() == "c:\\windows\\system32\\main.exe"
        )
    ]
    return CaseRuntime()


def profile_pma_1201_deep(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    set_main_command_line(cfg, "svchost.exe")
    ensure_user_module(cfg, "psapi", "0x71000000", "C:\\Windows\\system32\\psapi.dll")
    return CaseRuntime()


def profile_pma_1202_deep(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    cfg["timeout"] = 2
    set_main_command_line(cfg, "svchost.exe")
    return CaseRuntime()


def profile_pma_1203_deep(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    cfg["timeout"] = 2
    set_main_command_line(cfg, "svchost.exe")
    return CaseRuntime()


def profile_pma_1204_deep(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    ensure_user_module(cfg, "psapi", "0x71000000", "C:\\Windows\\system32\\psapi.dll")
    ensure_user_module(cfg, "sfc_os", "0x5fe00000", "C:\\Windows\\system32\\sfc_os.dll")
    return CaseRuntime()


def profile_pma_1402(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    cfg["timeout"] = 6
    cfg["max_api_count"] = 800
    cfg.setdefault("api_hammering", {})
    cfg["api_hammering"]["enabled"] = True
    cfg["api_hammering"]["threshold"] = 50
    return CaseRuntime()


def profile_pma_1603(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    cfg.setdefault("exceptions", {})
    cfg["exceptions"]["dispatch_handlers"] = True
    return CaseRuntime()


def profile_pma_1702(cfg: dict[str, Any], _: Path) -> CaseRuntime:
    cfg["timeout"] = 4
    cfg["max_api_count"] = 600
    cfg.setdefault("api_hammering", {})
    cfg["api_hammering"]["enabled"] = True
    cfg["api_hammering"]["threshold"] = 100
    return CaseRuntime()


def profile_pma_0101_staged(cfg: dict[str, Any], tmp_path: Path) -> CaseRuntime:
    cfg["timeout"] = 20
    cfg["max_api_count"] = 200
    cfg.setdefault("exceptions", {})
    cfg["exceptions"]["dispatch_handlers"] = True

    source = TESTS_DIR / "capa-testfiles"
    sample_path = tmp_path / "sample.exe"
    shutil.copy2(source / "Practical Malware Analysis Lab 01-01.exe_", sample_path)
    shutil.copy2(source / "Practical Malware Analysis Lab 01-01.dll_", tmp_path / "Lab01-01.dll")
    shutil.copy2(source / "kernel32.dll_", tmp_path / "Kernel32.dll")

    return CaseRuntime(
        sample_path=sample_path,
        argv=("WARNING_THIS_WILL_DESTROY_YOUR_MACHINE",),
        volumes=(f"{tmp_path}:C:\\Windows\\system32",),
    )
