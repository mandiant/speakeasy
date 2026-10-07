from speakeasy.profiler_events import ApiArg
from speakeasy.winenv.api import api, sigdb, sigfmt


def _sig(*codes: str) -> sigdb.FuncSig:
    params = tuple(sigdb.ParamSig(f"p{i}", code, "i") for i, code in enumerate(codes))
    return sigdb.FuncSig("Func", "test", "u32", params)


def _signature_args() -> api.HandlerArgs:
    rendered = [
        sigfmt.RenderedArg("0x1000", "ptr"),
        sigfmt.RenderedArg("F_ONE", "flags"),
        sigfmt.RenderedArg("0x44", "handle"),
    ]
    return api.HandlerArgs.from_signature(_sig("S", "u32", "h"), 4, rendered, [0x1000, 1, 0x44])


def test_handler_display_by_name_replaces_rendering() -> None:
    args = _signature_args()
    args["p0"].display = "C:\\x"
    args["p2"].display = "\\Device\\Foo"
    assert args.get_report_args() == [
        ApiArg(name="p0", type="str", value=0x1000, display="C:\\x"),
        ApiArg(name="p1", type="flags", value=1, display="F_ONE"),
        ApiArg(name="p2", type="text", value=0x44, display="\\Device\\Foo"),
    ]


def test_handler_display_by_index_with_signature_uses_param_index() -> None:
    args = api.HandlerArgs.from_signature(
        _sig("u64", "u32"), 4, [sigfmt.RenderedArg("0x200000001", "int"), sigfmt.RenderedArg("0x3", "int")], [1, 2, 3]
    )
    args[1].display = "COND"
    assert args.get_report_args() == [
        ApiArg(name="p0", type="int", value=0x200000001, display="0x200000001"),
        ApiArg(name="p1", type="text", value=3, display="COND"),
    ]


def test_handler_display_keeps_signature_enum_and_flags() -> None:
    args = _signature_args()
    args["p1"].display = "FLAG_ONE"
    assert args["p1"].display == "F_ONE"
    assert args["p1"].type == "flags"


def test_handler_display_without_signature_by_slot() -> None:
    args = api.HandlerArgs.from_slots([0x1000, 2])
    args[0].display = "C:\\x"
    assert args.get_report_args() == [
        ApiArg(type="text", value=0x1000, display="C:\\x"),
        ApiArg(type="int", value=2, display="0x2"),
    ]


def test_handler_type_is_settable() -> None:
    args = api.HandlerArgs.from_slots([0x1000])
    args[0].display = "C:\\x"
    args[0].type = "str"
    assert args.get_report_args() == [ApiArg(type="str", value=0x1000, display="C:\\x")]


def test_unknown_name_or_index_is_detached() -> None:
    args = api.HandlerArgs.from_slots([1])
    args["lpFileName"].display = "lost"
    args[5].display = "lost"
    sig_args = _signature_args()
    sig_args["NoSuchParam"].display = "lost"
    assert args.get_report_args() == [ApiArg(type="int", value=1, display="0x1")]
    assert [a.display for a in sig_args.get_report_args()] == ["0x1000", "F_ONE", "0x44"]


def test_variadic_handler_appends_entries() -> None:
    args = api.HandlerArgs.from_slots([0x2000, 0x3000])
    args[1].display = "%s=%d"
    args.append("x=1")
    assert args.get_report_args() == [
        ApiArg(type="int", value=0x2000, display="0x2000"),
        ApiArg(type="text", value=0x3000, display="%s=%d"),
        ApiArg(type="text", display="x=1"),
    ]
    args.clear()
    args.append("out", type="str")
    assert args.get_report_args() == [ApiArg(type="str", display="out")]


def test_no_context_discards_writes() -> None:
    api.NO_CONTEXT.args.append("lost")
    api.NO_CONTEXT.args[0].display = "lost"
    api.NO_CONTEXT.args["lpFileName"].display = "lost"
    assert api.NO_CONTEXT.args.get_report_args() == []
    assert api.NO_CONTEXT.func_name == ""
