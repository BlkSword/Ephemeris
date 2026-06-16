"""Integration tests for the ephemeris Python package."""

import pytest
import ephemeris


class TestKeyWrap:
    def test_roundtrip(self):
        salt = ephemeris.generate_salt()
        params = ephemeris.Argon2Params.low_memory()
        key = b"this is a test key for wrapping 32b"
        blob = ephemeris.wrap_key(key, b"password", salt, params)
        recovered = ephemeris.unwrap_key(blob, b"password", salt, params)
        assert recovered == key

    def test_wrong_password(self):
        salt = ephemeris.generate_salt()
        params = ephemeris.Argon2Params.low_memory()
        key = b"test key material here 32 bytes"
        blob = ephemeris.wrap_key(key, b"correct", salt, params)
        recovered = ephemeris.unwrap_key(blob, b"wrong", salt, params)
        assert recovered != key

    def test_unwrap_never_fails(self):
        salt = ephemeris.generate_salt()
        params = ephemeris.Argon2Params.low_memory()
        blob = b"\x00" * 64
        for pw in [b"a", b"correct", b"", b"wrong"]:
            result = ephemeris.unwrap_key(blob, pw, salt, params)
            assert len(result) == 64

    def test_bad_salt_length(self):
        with pytest.raises(ValueError, match="salt must be exactly 16 bytes"):
            ephemeris.wrap_key(b"key", b"pw", b"short", ephemeris.Argon2Params.low_memory())


class TestRepudiate:
    def test_basic(self):
        salt = ephemeris.generate_salt()
        params = ephemeris.Argon2Params.low_memory()
        ct = b"ABCDEFGHIJ"  # 10 bytes
        fake_msg = b"0123456789"  # 10 bytes
        blob = ephemeris.repudiate(ct, fake_msg, b"fake-pw", salt, params)
        assert len(blob) == 10

    def test_mismatched_lengths(self):
        salt = ephemeris.generate_salt()
        params = ephemeris.Argon2Params.low_memory()
        with pytest.raises(ValueError, match="length mismatch"):
            ephemeris.repudiate(b"12345", b"123", b"pw", salt, params)


class TestFileFormat:
    def test_eph_roundtrip(self):
        salt = ephemeris.generate_salt()
        key_blob = b"0123456789"
        ct = b"ABCDEFGHIJ"
        data = ephemeris.build_eph(salt, key_blob, ct)
        parsed_salt, parsed_key, parsed_ct = ephemeris.parse_eph(data)
        assert parsed_salt == salt
        assert parsed_key == key_blob
        assert parsed_ct == ct

    def test_key_roundtrip(self):
        salt = ephemeris.generate_salt()
        key_blob = b"some-key-material"
        data = ephemeris.build_key(salt, key_blob)
        parsed_salt, parsed_blob = ephemeris.parse_key(data)
        assert parsed_salt == salt
        assert parsed_blob == key_blob

    def test_bad_magic(self):
        with pytest.raises(ValueError, match="invalid magic"):
            ephemeris.parse_eph(b"BAD!" + b"\x00" * 30)

    def test_truncated(self):
        with pytest.raises(ValueError, match="unexpected end of file"):
            ephemeris.parse_eph(b"EPH1")


class TestHighLevel:
    def test_encrypt_decrypt_roundtrip(self):
        msg = b"sensitive message for testing"
        pw = b"my-secret-password"
        data = ephemeris.encrypt(msg, pw)
        assert ephemeris.decrypt(data, pw) == msg

    def test_wrong_password_gives_garbage(self):
        msg = b"sensitive data here"
        data = ephemeris.encrypt(msg, b"correct")
        result = ephemeris.decrypt(data, b"wrong")
        assert result != msg
        assert len(result) == len(msg)

    def test_repudiate_flow(self):
        real = b"AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHH"
        fake = b"0000011111222223333344444555556666677777"
        assert len(real) == len(fake)

        data = ephemeris.encrypt(real, b"real-pw")
        fake_data = ephemeris.repudiate_eph(data, fake, b"fake-pw")

        assert ephemeris.decrypt(fake_data, b"fake-pw") == fake
        assert ephemeris.decrypt(fake_data, b"real-pw") != real

    def test_invalid_eph_rejected(self):
        with pytest.raises(ValueError, match="unexpected end of file"):
            ephemeris.decrypt(b"not an eph file", b"password")

    def test_empty_message(self):
        data = ephemeris.encrypt(b"", b"pw")
        assert ephemeris.decrypt(data, b"pw") == b""
        fake_data = ephemeris.repudiate_eph(data, b"", b"fake-pw")
        assert ephemeris.decrypt(fake_data, b"fake-pw") == b""


class TestArgon2Params:
    def test_defaults(self):
        params = ephemeris.Argon2Params.default_params()
        assert "memory_cost=37888" in repr(params)

    def test_custom(self):
        params = ephemeris.Argon2Params(time_cost=4, memory_cost=65536, parallelism=2)
        assert "time_cost=4" in repr(params)

    def test_low_memory(self):
        params = ephemeris.Argon2Params.low_memory()
        assert "time_cost=1" in repr(params)
        assert "memory_cost=1024" in repr(params)
