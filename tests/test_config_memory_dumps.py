from speakeasy.config import SpeakeasyConfig


def test_capture_memory_dumps_defaults_false():
    """Config accepts capture_memory_dumps and defaults to False."""
    data = {
        "config_version": 0.2,
        "emu_engine": "unicorn",
        "timeout": 60,
        "system": "windows",
        "analysis": {"memory_tracing": False, "strings": True, "coverage": False},
        "exceptions": {"dispatch_handlers": True},
        "os_ver": {},
        "current_dir": "C:\\Windows",
        "hostname": "test",
        "user": {"name": "test"},
        "filesystem": {"files": []},
        "network": {
            "dns": {"names": {}},
            "http": {"responses": []},
            "winsock": {"responses": []},
            "adapters": [],
        },
        "modules": {
            "module_directory_x86": "",
            "module_directory_x64": "",
        },
    }
    cfg = SpeakeasyConfig.model_validate(data)
    assert cfg.capture_memory_dumps is False


def test_capture_memory_dumps_enabled():
    data = {
        "config_version": 0.2,
        "emu_engine": "unicorn",
        "timeout": 60,
        "system": "windows",
        "capture_memory_dumps": True,
        "analysis": {"memory_tracing": False, "strings": True, "coverage": False},
        "exceptions": {"dispatch_handlers": True},
        "os_ver": {},
        "current_dir": "C:\\Windows",
        "hostname": "test",
        "user": {"name": "test"},
        "filesystem": {"files": []},
        "network": {
            "dns": {"names": {}},
            "http": {"responses": []},
            "winsock": {"responses": []},
            "adapters": [],
        },
        "modules": {
            "module_directory_x86": "",
            "module_directory_x64": "",
        },
    }
    cfg = SpeakeasyConfig.model_validate(data)
    assert cfg.capture_memory_dumps is True
