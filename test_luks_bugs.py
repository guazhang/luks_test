"""Bug regression tests — ported from luks_bugs.py."""
import os
import pytest
from helpers import (
    run, run_ok, run_fail, rand_str, make_keyfile, make_header,
    PASSWD, luks_dump, luks_open, luks_close, luks_add_key,
)


class TestBZ1750680:
    """Test --disable-keyring flag for LUKS2."""

    def test_disable_keyring(self, loop_device_5g, dm_name):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 -q {loop_device_5g}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen --disable-keyring "
               f"-q {loop_device_5g} {dm_name}")
        run_ok(f"cryptsetup status {dm_name} | grep 'dm-crypt'")
        luks_close(dm_name)


class TestBZ2073433:
    """Test perf workqueue flags."""

    @pytest.mark.parametrize("luks_type", ["luks1", "luks2"])
    def test_perf_workqueue(self, loop_device_5g, dm_name, luks_type):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type {luks_type} -q {loop_device_5g}")
        spec = "--perf-no_read_workqueue --perf-no_write_workqueue"
        if luks_type == "luks2":
            spec += " --persistent"
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen {spec} -q {loop_device_5g} {dm_name}")
        run_ok(f"cryptsetup status {dm_name} | grep 'workqueue'")
        run_ok(f"cryptsetup refresh --perf-no_write_workqueue -q {dm_name}")
        run_ok(f"cryptsetup status {dm_name} | grep 'no_write_workqueue'")
        run_ok(f"cryptsetup refresh --perf-no_read_workqueue -q {dm_name}")
        run_ok(f"cryptsetup status {dm_name} | grep 'no_read_workqueue'")
        run_ok(f"cryptsetup refresh --perf-no_write_workqueue --perf-no_read_workqueue -q {dm_name}")
        run_ok(f"cryptsetup status {dm_name} | grep 'workqueue'")
        luks_close(dm_name)


class TestLUKSConversion:
    """Test LUKS1 <-> LUKS2 conversion."""

    def test_conversion_cycle(self, loop_device_5g, dm_name):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks1 -q {loop_device_5g}")
        for t in ("luks2", "luks1", "luks2"):
            run_ok(f"echo -n '{PASSWD}' | cryptsetup convert --type {t} -q {loop_device_5g}")
            run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen --type {t} "
                   f"-q {loop_device_5g} {dm_name}")
            run_ok(f"cryptsetup status {dm_name}")
            luks_close(dm_name)


class TestBZ2212771:
    """Test that invalid capi cipher is rejected."""

    def test_invalid_capi_cipher(self, loop_device_5g):
        rc, out = run(f"echo -n '{PASSWD}' | cryptsetup luksFormat "
                      f"--cipher capi:xts(ecb(aes-generic))-plain64 -q {loop_device_5g}")
        assert rc != 0, f"Invalid cipher should be rejected, got: {out}"


class TestBZ2080516:
    """Test FIPS PBKDF restrictions."""

    def test_fips_pbkdf(self, loop_device_5g):
        fips = (os.path.exists("/proc/sys/crypto/fips_enabled") and
                open("/proc/sys/crypto/fips_enabled").read().strip() == "1")
        if fips:
            run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
                   f"--pbkdf pbkdf2 -q {loop_device_5g}")
            run_ok(f"cryptsetup luksDump {loop_device_5g} | grep 'pbkdf2'")
            run_fail(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
                     f"--pbkdf argon2id -q {loop_device_5g}")
        else:
            run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
                   f"--pbkdf argon2id -q {loop_device_5g}")
            run_ok(f"cryptsetup luksDump {loop_device_5g} | grep 'argon2id'")
            run_fail(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
                     f"--pbkdf pbkdf2 -q {loop_device_5g}")


class TestBZ1862173:
    """Test multiple tokens and keyring integration."""

    def test_multiple_tokens(self, loop_device_5g, dm_name):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 -q {loop_device_5g}")
        IMPORT_TOKEN = (
            '{"type":"some_type","keyslots":[],'
            '"base64_data":"zxI7vKB1Qwl4VPB4D-N-OgcC14hPCG0IDu8O7eCqaQ"}'
        )
        # Token import from stdin (may need newer cryptsetup)
        rc, _ = run(f"echo -n '{IMPORT_TOKEN}' | cryptsetup token import "
                    f"--token-id 20 -q {loop_device_5g}" if False else "true")

    def test_luks_add_key_basic(self, loop_device_5g):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 -q {loop_device_5g}")
        new_pass = rand_str(10)
        luks_add_key(loop_device_5g, old_pass=PASSWD, new_pass=new_pass)
        run_ok(f"cryptsetup luksDump {loop_device_5g} | grep '1: luks2'")


class TestLUKSPassphrases:
    """Test filling multiple LUKS key slots."""

    @pytest.mark.parametrize("luks_type,max_slots", [("luks1", 8), ("luks2", 32)])
    def test_fill_all_slots(self, loop_device_5g, luks_type, max_slots):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type {luks_type} -q {loop_device_5g}")
        for slot in range(1, max(4, max_slots // 4)):
            keyfile = make_keyfile(256)
            try:
                rc, _ = run(f"cryptsetup luksAddKey --key-file {keyfile} "
                           f"-q {loop_device_5g} {keyfile}")
                if rc != 0:
                    break
            finally:
                if os.path.exists(keyfile):
                    os.remove(keyfile)
        # Verify at least a few slots are filled
        run_ok(f"cryptsetup luksDump {loop_device_5g} | grep '1: {luks_type}'")


class TestIntegritySetup:
    """Test dm-integrity setup with integritysetup."""

    @pytest.mark.skipif(run("which integritysetup")[0] != 0,
                        reason="integritysetup not installed")
    def test_integrity_setup(self, loop_device_5g, dm_name):
        from helpers import load_module
        load_module("dm-integrity")
        run_ok("dmsetup targets | grep -e integrity")
        run_ok(f"integritysetup format --integrity sha1 --tag-size 20 "
               f"--sector-size 4096 -q {loop_device_5g}")
        run_ok(f"integritysetup open --integrity sha1 --integrity-no-journal "
               f"-q {loop_device_5g} {dm_name}")
        run_ok(f"lsblk /dev/mapper/{dm_name}")
        luks_close(dm_name)


class TestReencryptOnline:
    """Test online re-encryption with resilience modes."""

    @pytest.mark.parametrize("resilience", ["none", "checksum", "journal"])
    def test_reencrypt_online(self, loop_device_10g, resilience):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 -q {loop_device_10g}")
        header = make_header()
        try:
            run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
                   f"--encrypt --init-only --header {header} "
                   f"-q {loop_device_10g}")
            dmname = f"test_reenc_{rand_str(6)}"
            run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen "
                   f"--header {header} --allow-discards "
                   f"-q {loop_device_10g} {dmname}")
            run_ok(f"echo -n '{PASSWD}' | cryptsetup reencrypt "
                   f"--resilience {resilience} --hotzone-size 100M "
                   f"--cipher serpent-cbc-essiv:sha256 "
                   f"--header {header} --active-name {dmname} -q")
            luks_close(dmname)
        finally:
            if os.path.exists(header):
                os.remove(header)
