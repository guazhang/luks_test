"""LUKS re-encryption tests — ported from luks_reencrypt.py."""
import os
import pytest
from helpers import (
    run, run_ok, run_fail, rand_str, make_keyfile, make_header,
    PASSWD, luks_status, luks_open, luks_close,
)


class TestReencryptBasic:
    """Basic re-encryption tests."""

    def test_basic_reencrypt(self, loop_device_10g, dm_name):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
               f"--key-size 128 --cipher aes-cbc-essiv:sha256 "
               f"--offset 8192 --pbkdf-force-iterations 1000 "
               f"--pbkdf-memory 32 --pbkdf-parallel 1 -q {loop_device_10g}")

        run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
               f"--key-size 256 --cipher twofish-cbc-essiv:sha256 "
               f"--resilience journal --pbkdf-force-iterations 1000 "
               f"--pbkdf-memory 32 --pbkdf-parallel 1 -q {loop_device_10g}")

        run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
               f"--key-size 128 --cipher aes-cbc-essiv:sha256 "
               f"--resilience checksum --pbkdf-force-iterations 1000 "
               f"--pbkdf-memory 32 --pbkdf-parallel 1 -q {loop_device_10g}")

        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen "
               f"-q {loop_device_10g} {dm_name}")
        run_ok(f"cryptsetup status {dm_name}")
        luks_close(dm_name)

    def test_init_only_then_resume(self, loop_device_10g, dm_name):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
               f"--pbkdf-force-iterations 1000 --pbkdf-memory 32 "
               f"--pbkdf-parallel 1 -q {loop_device_10g}")

        run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
               f"--cipher aes-xts-plain64 --init-only "
               f"--pbkdf-force-iterations 1000 --pbkdf-memory 32 "
               f"--pbkdf-parallel 1 -q {loop_device_10g}")

        run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
               f"--key-size 128 --cipher aes-cbc-essiv:sha256 "
               f"--resilience checksum --pbkdf-force-iterations 1000 "
               f"--pbkdf-memory 32 --pbkdf-parallel 1 -q {loop_device_10g}")

        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen "
               f"-q {loop_device_10g} {dm_name}")
        luks_close(dm_name)

    @pytest.mark.parametrize("reduce_size", ["8M", "21M", "33M", "64M"])
    def test_reencrypt_data_shift(self, loop_device_10g, reduce_size):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
               f"--reduce-device-size {reduce_size} --encrypt "
               f"--pbkdf-force-iterations 1000 --pbkdf-memory 32 "
               f"--pbkdf-parallel 1 -q {loop_device_10g}")
        run_ok(f"dd if=/dev/zero of={loop_device_10g} bs=1M count=10 2>/dev/null")
        run_ok(f"wipefs -a {loop_device_10g}")

    def test_reencrypt_init_only_with_dmname(self, loop_device_10g):
        dmname = f"reenc_dm_{rand_str(6)}"
        run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
               f"--key-size 128 --reduce-device-size 8M "
               f"--cipher aes-cbc-essiv:sha256 --encrypt --init-only "
               f"{dmname} --pbkdf-force-iterations 1000 "
               f"--pbkdf-memory 32 --pbkdf-parallel 1 -q {loop_device_10g}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
               f"--resume-only -q {loop_device_10g}")


class TestReencryptWithHeader:
    """Re-encryption with detached header."""

    @pytest.mark.parametrize("cipher,resilience", [
        ("aes-cbc-essiv:sha256", "none"),
        ("twofish-cbc-essiv:sha256", "journal"),
        ("serpent-xts-plain", "checksum"),
    ])
    def test_reencrypt_with_header(self, loop_device_10g, cipher, resilience):
        header = make_header()
        try:
            run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
                   f"--header {header} --encrypt --cipher {cipher} "
                   f"--key-size 128 --resilience {resilience} "
                   f"--pbkdf-force-iterations 1000 --pbkdf-memory 32 "
                   f"--pbkdf-parallel 1 -q {loop_device_10g}")
            assert os.path.getsize(header) > 0
        finally:
            os.remove(header)
        run_ok(f"dd if=/dev/zero of={loop_device_10g} bs=1M count=10 2>/dev/null")
        run_ok(f"wipefs -a {loop_device_10g}")

    def test_reencrypt_then_decrypt_with_header(self, loop_device_10g):
        header = make_header()
        try:
            run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
                   f"--key-size 128 --cipher aes-cbc-essiv:sha256 "
                   f"--sector-size 512 --header {header} "
                   f"--pbkdf-force-iterations 1000 --pbkdf-memory 32 "
                   f"--pbkdf-parallel 1 -q {loop_device_10g}")
            run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
                   f"--header {header} --decrypt -q {loop_device_10g}")
        finally:
            os.remove(header)

    def test_reencrypt_with_offset_and_header(self, loop_device_10g):
        header = make_header()
        try:
            run_ok(f"dd if=/dev/urandom of={loop_device_10g} bs=512 count=32768")
            run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
                   f"--encrypt --offset 32768 --header {header} "
                   f"--pbkdf-force-iterations 1000 --pbkdf-memory 32 "
                   f"--pbkdf-parallel 1 -q {loop_device_10g}")
        finally:
            os.remove(header)

    @pytest.mark.parametrize("resilience,cipher", [
        ("journal", "aes-cbc-essiv:sha256"),
        ("none", "twofish-cbc-essiv:sha256"),
        ("checksum", "serpent-xts-plain"),
    ])
    def test_reencrypt_multi_step_with_header(self, loop_device_10g, resilience, cipher):
        header = make_header()
        try:
            run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
                   f"--header {header} --cipher {cipher} "
                   f"--pbkdf-force-iterations 1000 --pbkdf-memory 32 "
                   f"--pbkdf-parallel 1 -q {loop_device_10g}")

            dmname = f"reenc_ms_{rand_str(6)}"
            run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen "
                   f"--header {header} -q {loop_device_10g} {dmname}")

            run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
                   f"--header {header} --active-name {dmname} "
                   f"--resilience {resilience} "
                   f"--pbkdf-force-iterations 1000 --pbkdf-memory 32 "
                   f"--pbkdf-parallel 1 -q {loop_device_10g}")
            luks_close(dmname)

            run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
                   f"--header {header} --resilience {resilience} "
                   f"--decrypt --pbkdf-force-iterations 1000 "
                   f"--pbkdf-memory 32 --pbkdf-parallel 1 "
                   f"-q {loop_device_10g}")
        finally:
            os.remove(header)


class TestReencryptSectorSize:
    """Re-encryption with different sector sizes."""

    def test_reencrypt_sector_size_4096(self, loop_device_10g):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
               f"--pbkdf-force-iterations 1000 --pbkdf-memory 32 "
               f"--pbkdf-parallel 1 -q {loop_device_10g}")

        rc, out = run(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
                      f"--sector-size 4096 --force-offline-reencrypt "
                      f"--pbkdf-force-iterations 1000 --pbkdf-memory 32 "
                      f"--pbkdf-parallel 1 -q {loop_device_10g}")
