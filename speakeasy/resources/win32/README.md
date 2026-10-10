# Windows API data

The build generates two signature files, which are not committed. `win32json_signatures.json.gz` holds function prototypes, enums and structs from win32metadata (`deps/win32json`, via `scripts/gen_win32_signatures.py`). `phnt_signatures.json.gz` holds native API prototypes from phnt (`deps/phnt`, via `scripts/gen_phnt_signatures.py`).

`exports/` holds the physical export tables of real Windows modules, with names, ordinals and forwarders. It is maintained by hand. See `exports/README.md`.
