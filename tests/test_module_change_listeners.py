"""Observer failures must not interrupt coherent module load or discard."""

from tests.test_module_load_rollback import assert_image_unmapped, guest_image
from tests.test_module_load_rollback import warm_emu as warm_emu
from tests.test_peb_module_links import assert_process_rings


def test_load_and_discard_isolate_each_listener_failure(warm_emu, caplog):
    emu = warm_emu
    base, _ = emu.get_valid_ranges(0x5000, addr=0x6B000000)
    image = guest_image(emu, "listener_guest", base)
    observed = []

    def broken():
        observed.append("broken")
        raise RuntimeError("observer failure")

    def healthy():
        observed.append((emu.get_mod_by_name(image.name), list(emu.modules)))

    emu.module_change_listeners.extend([broken, healthy, broken, healthy])
    module = emu.load_image(image)
    assert observed == ["broken", (module, list(emu.modules)), "broken", (module, list(emu.modules))]
    assert module.base in emu.get_current_process()._peb_modules
    assert emu.api_registry.lookup(module, "GuestStep") is not None
    assert emu._load_depth == 0
    assert_process_rings(emu.get_current_process())

    observed.clear()
    emu._discard_loaded_module(module)
    assert observed == ["broken", (None, list(emu.modules)), "broken", (None, list(emu.modules))]
    assert module.base not in emu.get_current_process()._peb_modules
    assert id(module) not in emu.api_registry.names
    assert_image_unmapped(emu, base, image.image_size)
    assert_process_rings(emu.get_current_process())
    failures = [record for record in caplog.records if "module change listener failed" in record.message]
    assert len(failures) == 4
    assert all(record.exc_info[0] is RuntimeError for record in failures)
