from speakeasy.winenv.codepage import decode_ansi, encode_ansi


def test_each_byte_decodes_to_one_character_and_encodes_back() -> None:
    data = bytes(range(256))
    text = decode_ansi(data)
    assert len(text) == 256
    assert encode_ansi(text) == data


def test_bytes_that_cp1252_does_not_define_decode_to_c1_controls() -> None:
    assert decode_ansi(b"\x81\x8d\x8f\x90\x9d") == "\x81\x8d\x8f\x90\x9d"
