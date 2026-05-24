"""LUKS2 compatibility tests — ported from luks_luks2.py compat_test2."""
import os
import pytest
from helpers import (
    run, run_ok, run_fail, rand_str, make_keyfile, make_header,
    PASSWD, luks_dump, luks_status, luks_open, luks_close,
    luks_add_key, check_cmd_opt,
)


def luks2_format(device, extra_opts=""):
    """Helper: format a device as LUKS2 with PBKDF2."""
    run_ok(
        f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
        f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
        f"{extra_opts} -q {device}"
    )


class TestLUKS2Format:
    """LUKS2 format validation."""

    def test_basic_format(self, loop_device_5g):
        luks2_format(loop_device_5g)
        dump = luks_dump(loop_device_5g)
        assert "keyslots" in dump or "Keyslots" in dump

    def test_dump_master_key(self, loop_device_5g):
        luks2_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksDump --dump-master-key -q {loop_device_5g} "
               f"| grep 'MK dump:'")

    def test_wrong_passphrase_fails(self, loop_device_5g):
        luks2_format(loop_device_5g)
        run_fail(f"echo -n 'wrong_passwd' | cryptsetup open --test-passphrase -q {loop_device_5g}")

    def test_open_close(self, loop_device_5g, dm_name):
        luks2_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {loop_device_5g} {dm_name}")
        assert os.path.exists(f"/dev/mapper/{dm_name}")
        luks_close(dm_name)

    @pytest.mark.parametrize("sector_size,expect_ok", [
        (511, False), (256, False), (8192, False),
        (512, True), (1024, True), (2048, True), (4096, True),
    ])
    def test_sector_size_validation(self, loop_device_5g, sector_size, expect_ok):
        cmd = (
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
            f"--sector-size {sector_size} -q {loop_device_5g}"
        )
        rc, _ = run(cmd)
        assert (rc == 0) == expect_ok, \
            f"sector-size {sector_size}: expected ok={expect_ok}, got rc={rc}"

    @pytest.mark.parametrize("offset,expect_ok", [
        (1, False), (16385, False), (32, False), (16384, True),
    ])
    def test_offset_validation(self, loop_device_5g, offset, expect_ok):
        cmd = (
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
            f"--offset {offset} -q {loop_device_5g}"
        )
        rc, _ = run(cmd)
        assert (rc == 0) == expect_ok, \
            f"offset {offset}: expected ok={expect_ok}, got rc={rc}"

    @pytest.mark.parametrize("align_payload", [5, 32, 8192])
    def test_align_payload(self, loop_device_5g, align_payload):
        luks2_format(loop_device_5g, extra_opts=f"--align-payload {align_payload}")

    def test_offset_with_align_payload(self, loop_device_5g):
        run_ok(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
            f"--offset 16384 -q {loop_device_5g}"
        )
        run_ok(f"cryptsetup luksDump {loop_device_5g} | "
               f"grep 'offset: {512 * 16384}'")

    @pytest.mark.parametrize("cipher,key_size", [
        ("aes-cbc-essiv:sha256", 128),
        ("aes-cbc-essiv:sha256", 256),
        ("aes-xts-plain64", 256),
        ("aes-xts-plain64", 512),
        ("aes-ecb", 256),
        ("aes-cbc-plain64", 256),
        ("aes-cbc-null", 256),
    ])
    def test_format_ciphers(self, loop_device_5g, cipher, key_size):
        rc, out = run(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
            f"--cipher {cipher} --key-size {key_size} -q {loop_device_5g}"
        )
        assert rc == 0, f"LUKS2 format failed with {cipher}/{key_size}: {out}"

    @pytest.mark.parametrize("hash_alg", ["sha256", "sha512"])
    def test_format_with_hash(self, loop_device_5g, hash_alg):
        run_ok(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 --hash {hash_alg} "
            f"--cipher aes-cbc-essiv:sha256 --key-size 128 -q {loop_device_5g}"
        )
        run_ok(f"cryptsetup luksDump {loop_device_5g} | grep -q '{hash_alg}'")


class TestLUKS2KeyManagement:
    """LUKS2 key operations."""

    def test_add_remove_key(self, loop_device_5g, dm_name):
        new_pass = rand_str(10)
        luks2_format(loop_device_5g)
        luks_add_key(loop_device_5g, old_pass=PASSWD, new_pass=new_pass,
                     pbkdf="pbkdf2", pbkdf_force_iterations=1000)
        run_ok(f"echo -n '{new_pass}' | cryptsetup open --test-passphrase -q {loop_device_5g}")

    def test_kill_slot_wrong_passwd(self, loop_device_5g):
        luks2_format(loop_device_5g)
        run_fail(f"echo -n 'wrong' | cryptsetup luksKillSlot -q {loop_device_5g} 1")

    def test_kill_slot_and_cant_open(self, loop_device_5g):
        luks2_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksKillSlot -q {loop_device_5g} 0")
        run_fail(f"echo -n '{PASSWD}' | cryptsetup open --test-passphrase -q {loop_device_5g}")

    def test_keyfile_offset_operations(self, loop_device_5g, dm_name, keyfile_128):
        keyfile2 = make_keyfile(32)
        try:
            run_ok(f"cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 "
                   f"--pbkdf-force-iterations 1000 --key-slot 0 "
                   f"--keyfile-size 13 --keyfile-offset 16 "
                   f"--key-file {keyfile_128} -q {loop_device_5g}")
            run_fail(f"cryptsetup luksOpen --key-file {keyfile_128} "
                     f"--keyfile-size 13 --keyfile-offset 15 "
                     f"-q {loop_device_5g} {dm_name}")
            run_ok(f"cryptsetup luksOpen --key-file {keyfile_128} "
                   f"--keyfile-size 13 --keyfile-offset 16 "
                   f"-q {loop_device_5g} {dm_name}")
            luks_close(dm_name)
        finally:
            if os.path.exists(keyfile2):
                os.remove(keyfile2)

    def test_keyfile_size_validation(self, loop_device_5g, dm_name, keyfile_128):
        run_ok(f"cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 "
               f"--pbkdf-force-iterations 1000 --key-slot 0 "
               f"--keyfile-size 13 --key-file {keyfile_128} -q {loop_device_5g}")
        run_fail(f"cryptsetup luksOpen --key-file {keyfile_128} --keyfile-size 0 "
                 f"-q {loop_device_5g} {dm_name}")
        run_fail(f"cryptsetup luksOpen --key-file {keyfile_128} --keyfile-size 14 "
                 f"-q {loop_device_5g} {dm_name}")
        run_ok(f"cryptsetup luksOpen --key-file {keyfile_128} --keyfile-size 13 "
               f"-q {loop_device_5g} {dm_name}")
        luks_close(dm_name)

    def test_delete_last_key(self, loop_device_5g):
        luks2_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksKillSlot -q {loop_device_5g} 0")
        run_fail(f"echo -n '{PASSWD}' | cryptsetup open --test-passphrase -q {loop_device_5g}")


class TestLUKS2Stacked:
    """LUKS2 stacked device tests."""

    def test_luks_on_luks(self, loop_device_5g, dm_name):
        luks2_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {loop_device_5g} {dm_name}")
        mapper = f"/dev/mapper/{dm_name}"
        luks2_format(mapper)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {mapper} dummy")
        luks_close("dummy")
        luks_close(dm_name)

    def test_dm_linear_luks2(self, loop_device_5g, dm_name):
        run_ok(f"dmsetup create {dm_name} --table '0 40960 linear {loop_device_5g} 2'")
        mapper = f"/dev/mapper/{dm_name}"
        luks2_format(mapper)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {mapper} dummy2")
        run_ok(f"dmsetup load {dm_name} --table '0 40962 error'")
        run_ok(f"dmsetup resume {dm_name}")
        luks_close("dummy2")
        run_ok(f"dmsetup remove --retry {dm_name}")


class TestLUKS2PBKDF:
    """LUKS2 PBKDF parameter tests."""

    def test_pbkdf2_iterations(self, loop_device_5g):
        run_ok(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1234 -q {loop_device_5g}"
        )
        run_ok(f"cryptsetup luksDump {loop_device_5g} | grep -q '1234'")

    def test_invalid_pbkdf_rejected(self, loop_device_5g):
        rc, _ = run(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdfXX -q {loop_device_5g}"
        )
        assert rc != 0

    def test_pbkdf2_iterations_too_low_fails(self, loop_device_5g):
        rc, _ = run(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 999 -q {loop_device_5g}"
        )
        assert rc != 0

    @pytest.mark.parametrize("pbkdf", ["argon2id", "argon2i"])
    def test_argon2(self, loop_device_5g, pbkdf):
        if os.path.exists("/proc/sys/crypto/fips_enabled"):
            with open("/proc/sys/crypto/fips_enabled") as f:
                if f.read().strip() == "1":
                    pytest.skip("FIPS mode enabled, argon2 not available")
        rc, out = run(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
            f"--pbkdf {pbkdf} --pbkdf-force-iterations 1000 "
            f"--pbkdf-memory 1234 --pbkdf-parallel 1 -q {loop_device_5g}"
        )
        assert rc == 0, f"Format with {pbkdf} failed: {out}"
        run_ok(f"cryptsetup luksDump {loop_device_5g} | grep -q '{pbkdf}'")

    def test_iter_time(self, loop_device_5g):
        run_ok(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --iter-time 500 -q {loop_device_5g}"
        )


class TestLUKS2Resize:
    """LUKS2 resize operations."""

    def test_resize_sectors(self, loop_device_5g, dm_name):
        luks2_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {loop_device_5g} {dm_name}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup resize -q --size 160 {dm_name}")
        run_ok(f"cryptsetup status {dm_name} | grep '160 sectors'")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup resize -q {dm_name}")
        luks_close(dm_name)

    def test_resize_device_size(self, loop_device_5g, dm_name):
        luks2_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {loop_device_5g} {dm_name}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup resize --device-size 8M -q {dm_name}")
        run_ok(f"cryptsetup status {dm_name} | grep '16384 sectors'")
        luks_close(dm_name)

    def test_resize_disable_keyring(self, loop_device_5g, dm_name):
        luks2_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen --disable-keyring "
               f"-q {loop_device_5g} {dm_name}")
        run_ok(f"echo -n ' ' | cryptsetup resize --size 160 {dm_name}")
        run_ok(f"cryptsetup status {dm_name} | grep '160 sectors'")
        luks_close(dm_name)


class TestLUKS2KeyslotPriority:
    """LUKS2 keyslot priority tests."""

    def test_keyslot_priority(self, loop_device_5g):
        new_pass = rand_str(10)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
               f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
               f"--key-slot 1 -q {loop_device_5g}")
        luks_add_key(loop_device_5g, old_pass=PASSWD, new_pass=new_pass, key_slot=5,
                     pbkdf="pbkdf2", pbkdf_force_iterations=1000)
        run_fail(f"cryptsetup config --key-slot 0 --priority prefer -q {loop_device_5g}")
        run_fail(f"cryptsetup config --key-slot 1 --priority wrong -q {loop_device_5g}")
        run_ok(f"cryptsetup config --key-slot 1 --priority ignore -q {loop_device_5g}")
        run_fail(f"echo -n '{PASSWD}' | cryptsetup open --test-passphrase -q {loop_device_5g}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup open --key-slot 1 "
               f"--test-passphrase -q {loop_device_5g}")
        run_ok(f"echo -n '{new_pass}' | cryptsetup open --test-passphrase -q {loop_device_5g}")
        run_ok(f"cryptsetup config --key-slot 1 --priority normal -q {loop_device_5g}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup open --test-passphrase -q {loop_device_5g}")


class TestLUKS2UnboundKeys:
    """LUKS2 unbound keyslot tests."""

    def test_add_unbound_key(self, loop_device_5g, keyfile_128):
        run_ok(f"cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 "
               f"--pbkdf-force-iterations 1000 --key-slot 5 "
               f"--key-file {keyfile_128} -q {loop_device_5g}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksAddKey --pbkdf pbkdf2 "
               f"--pbkdf-force-iterations 1000 --key-size 16 "
               f"-q --unbound {loop_device_5g}")

    def test_unbound_key_cannot_open(self, loop_device_5g, dm_name):
        new_pass = rand_str(10)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
               f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 -q {loop_device_5g}")
        run_ok(f"echo -e '{PASSWD}\\n{new_pass}' | cryptsetup luksAddKey "
               f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
               f"--key-size 32 -q --unbound --key-slot 2 {loop_device_5g}")
        run_ok(f"cryptsetup luksDump {loop_device_5g} | grep '2: luks2 (unbound)'")
        run_fail(f"echo -n '{new_pass}' | cryptsetup luksOpen -q {loop_device_5g} {dm_name}")


class TestLUKS2SuspendResume:
    """LUKS2 suspend/resume tests."""

    def test_suspend_resume(self, loop_device_5g, dm_name):
        luks2_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {loop_device_5g} {dm_name}")
        run_ok(f"cryptsetup luksSuspend -q {dm_name}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksResume -q {dm_name}")
        luks_close(dm_name)


class TestLUKS2DetachedHeader:
    """LUKS2 detached header operations."""

    def test_detached_header_format_and_open(self, loop_device_5g, header_file, dm_name):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
               f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
               f"--header {header_file} -q {loop_device_5g}")
        run_fail(f"cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 "
                 f"--pbkdf-force-iterations 1000 --header {header_file} "
                 f"--align-payload 1 -q {loop_device_5g}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen --header {header_file} "
               f"-q {loop_device_5g} {dm_name}")
        luks_close(dm_name)

    def test_detached_header_resize_suspend(self, loop_device_5g, header_file, dm_name):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
               f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
               f"--header {header_file} -q {loop_device_5g}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen --header {header_file} "
               f"-q {loop_device_5g} {dm_name}")
        run_ok(f"cryptsetup resize --header {header_file} -q --size 160 {dm_name}")
        run_ok(f"cryptsetup status {dm_name} | grep '160 sectors'")
        run_ok(f"cryptsetup luksSuspend --header {header_file} -q {dm_name}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksResume --header {header_file} -q {dm_name}")
        luks_close(dm_name)

    def test_detached_header_add_key_from_fake_device(self, loop_device_5g, header_file, keyfile_128):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
               f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
               f"--header {header_file} -q {loop_device_5g}")
        run_ok(f"cryptsetup luksAddKey --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
               f"--key-slot 5 --header {header_file} "
               f"-q _fakedev {keyfile_128}")
        run_ok(f"cryptsetup luksDump --header {header_file} _fakedev | "
               f"grep '5: luks2'")
        run_ok(f"cryptsetup luksKillSlot --header {header_file} -q _fakedev 5")
        run_fail(f"cryptsetup luksDump --header {header_file} _fakedev | "
                 f"grep '5: luks2'")


class TestLUKS2MetadataKeyslotsSize:
    """LUKS2 metadata and keyslots area size tests."""

    def test_luks2_metadata_keyslots_size(self, loop_device_5g):
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
               f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
               f"--luks2-metadata-size 128k --luks2-keyslots-size 128k -q {loop_device_5g}")

    @pytest.mark.parametrize("meta,keyslots,expect_ok", [
        ("128k", "127k", False), ("127k", "128k", False), ("128k", "128M", True),
    ])
    def test_metadata_keyslots_validation(self, loop_device_5g, meta, keyslots, expect_ok):
        cmd = (
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
            f"--luks2-metadata-size {meta} --luks2-keyslots-size {keyslots} "
            f"-q {loop_device_5g}"
        )
        rc, _ = run(cmd)
        assert (rc == 0) == expect_ok, \
            f"meta={meta} keyslots={keyslots}: expected ok={expect_ok}, got rc={rc}"


class TestLUKS2Conversion:
    """LUKS1 <-> LUKS2 conversion tests."""

    def test_luks1_to_luks2_conversion(self, loop_device_5g, keyfile_128):
        keyfile2 = make_keyfile(32)
        try:
            run_ok(f"cryptsetup luksFormat --type luks1 --pbkdf pbkdf2 "
                   f"--pbkdf-force-iterations 1000 --key-slot 5 "
                   f"--key-file {keyfile_128} -q {loop_device_5g}")
            run_ok(f"cryptsetup luksAddKey --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
                   f"--key-slot 1 --key-file {keyfile_128} "
                   f"-q {loop_device_5g} {keyfile2}")
            if check_cmd_opt("cryptsetup", "--dump-json-metadata"):
                run_fail(f"cryptsetup luksDump --dump-json-metadata -q {loop_device_5g}")
            run_ok(f"cryptsetup luksDump {loop_device_5g} | grep 'Key Slot 1: ENABLED'")
            run_ok(f"cryptsetup luksDump {loop_device_5g} | grep 'Key Slot 5: ENABLED'")
            run_ok(f"cryptsetup convert --type luks2 -q {loop_device_5g}")
            run_ok(f"cryptsetup luksDump {loop_device_5g} | grep '1: luks2'")
            run_ok(f"cryptsetup luksDump {loop_device_5g} | grep '5: luks2'")
            run_ok(f"cryptsetup convert --type luks1 -q {loop_device_5g}")
        finally:
            if os.path.exists(keyfile2):
                os.remove(keyfile2)

    def test_luks2_cannot_convert_with_1024_sector(self, loop_device_5g, keyfile_128):
        run_ok(f"cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 "
               f"--pbkdf-force-iterations 1000 --sector-size 1024 "
               f"--key-file {keyfile_128} -q {loop_device_5g}")
        run_fail(f"cryptsetup convert --type luks1 -q {loop_device_5g}")

    def test_isLuks(self, loop_device_5g, keyfile_128):
        run_ok(f"cryptsetup luksFormat --type luks1 --pbkdf pbkdf2 "
               f"--pbkdf-force-iterations 1000 --align-payload 4097 "
               f"--key-file {keyfile_128} -q {loop_device_5g}")
        run_ok(f"cryptsetup convert --type luks2 -q {loop_device_5g}")
        run_ok(f"cryptsetup isLuks -q {loop_device_5g}")
