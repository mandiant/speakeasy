# README quickstart example

*2026-02-27T11:36:18Z by Showboat 0.6.1*
<!-- showboat-id: 8e9d0f6e-4615-444a-9b2a-7fc09a202314 -->

Executable proof for the short CLI invocation/output snippet shown in README.md.

```bash
python3 - <<'PY'
import lzma
from pathlib import Path
src = Path('/Users/user/code/hex-rays/ida-sandbox-plugin/deps/speakeasy/tests/bins/dll_test_x86.dll.xz')
out = Path('/tmp/readme_dll_test_x86.dll')
out.write_bytes(lzma.open(src, 'rb').read())
print(out)
PY
/Users/user/code/hex-rays/ida-sandbox-plugin/deps/speakeasy/.venv/bin/python -m speakeasy -t /tmp/readme_dll_test_x86.dll --no-mp -o /tmp/readme_report.json 2>/dev/null
jq '{sha256, arch, filetype, entry_points: (.entry_points | length)}' /tmp/readme_report.json
```

```output
/tmp/readme_dll_test_x86.dll
{
  "sha256": "30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45",
  "arch": "x86",
  "filetype": "dll",
  "entry_points": 3
}
```

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Installation and Docker usage](install.md)
- [CLI reference](cli-reference.md)
- [Help and troubleshooting](help.md)
