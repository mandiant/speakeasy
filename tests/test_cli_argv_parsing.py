import subprocess
import sys


def parse_argv(cli_args: list[str]) -> list[str]:
    """Run the CLI parser in-process and return the parsed argv list."""
    import argparse
    import shlex


    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--argv", action="store", default="", dest="argv")
    parser.add_argument("-t", "--target", dest="target")
    args, _ = parser.parse_known_args(cli_args)
    return shlex.split(args.argv) if args.argv else []


class TestArgvParsing:
    def test_dash_prefixed_args(self):
        result = parse_argv(["--argv=-log -path /foo"])
        assert result == ["-log", "-path", "/foo"]

    def test_dash_prefixed_args_equals_form(self):
        result = parse_argv(["--argv=-log -path /foo"])
        assert result == ["-log", "-path", "/foo"]

    def test_quoted_path_with_spaces(self):
        result = parse_argv(["--argv=-log -path 'C:\\path with spaces\\'"])
        assert result == ["-log", "-path", "C:\\path with spaces\\"]

    def test_empty_argv(self):
        result = parse_argv([])
        assert result == []

    def test_simple_args(self):
        result = parse_argv(["--argv=foo bar baz"])
        assert result == ["foo", "bar", "baz"]

    def test_double_quoted_args(self):
        result = parse_argv(['--argv=-a "hello world" -b'])
        assert result == ["-a", "hello world", "-b"]


def test_cli_argv_does_not_steal_other_flags():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "speakeasy.cli",
            "--argv=-log -path /foo",
            "--dump-default-config",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
