"""LUKS1 compatibility tests — ported from luks_luks1.py compat_test."""
import os
import pytest
from helpers import (
    run, run_ok, run_fail, rand_str, make_keyfile, make_header,
    PASSWD, luks_dump, luks_status, luks_open, luks_close,
    luks_add_key, check_cmd_opt,
)


def luks1_format(device, extra_opts=""):
    """Helper: format a device as LUKS1 with PBKDF2."""
    run_ok(
        f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks1 "
        f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
        f"{extra_opts} -q {device}"
    )


class TestLUKS1Format:
    """LUKS1 format and basic operations."""

    def test_format_and_open(self, loop_device_5g, dm_name):
        luks1_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup open --test-passphrase -q {loop_device_5g}")

    def test_wrong_passphrase_rejected(self, loop_device_5g):
        luks1_format(loop_device_5g)
        rc, _ = run(f"echo -n 'wrong_passwd' | cryptsetup open --test-passphrase -q {loop_device_5g}")
        assert rc == 2, f"Expected exit code 2, got {rc}"

    def test_open_close(self, loop_device_5g, dm_name):
        luks1_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {loop_device_5g} {dm_name}")
        assert os.path.exists(f"/dev/mapper/{dm_name}")
        luks_close(dm_name)
        assert not os.path.exists(f"/dev/mapper/{dm_name}")

    def test_format_with_uuid(self, loop_device_5g):
        uuid = "12345678-1234-1234-1234-123456789abc"
        luks1_format(loop_device_5g, extra_opts=f"--uuid {uuid}")
        run_ok(f"cryptsetup luksDump {loop_device_5g} | grep -q '{uuid}'")
        run_ok(f"cryptsetup luksDump {loop_device_5g} | grep -q 'Key Slot 0: ENABLED'")

    def test_dump_master_key(self, loop_device_5g):
        luks1_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksDump --dump-master-key -q {loop_device_5g} "
               f"| grep 'MK dump:'")

    @pytest.mark.parametrize("cipher,key_size", [
        ("aes-cbc-essiv:sha256", 128),
        ("aes-cbc-essiv:sha256", 256),
        ("aes-xts-plain64", 256),
        ("aes-xts-plain64", 512),
    ])
    def test_format_with_ciphers(self, loop_device_5g, dm_name, cipher, key_size):
        run_ok(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks1 "
            f"--cipher {cipher} --key-size {key_size} "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 -q {loop_device_5g}"
        )
        rc, _ = luks_open(loop_device_5g, dm_name)
        assert rc, f"LUKS1 open failed with {cipher}/{key_size}"
        luks_close(dm_name)

    def test_format_with_hash(self, loop_device_5g, dm_name):
        run_ok(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks1 "
            f"--cipher aes-cbc-essiv:sha256 --key-size 128 --hash sha512 "
            f"--iter-time 1000 -q {loop_device_5g}"
        )
        luks_open(loop_device_5g, dm_name)
        luks_close(dm_name)


class TestLUKS1HeaderOps:
    """LUKS1 header backup, restore, and detached header."""

    def test_header_backup_and_restore(self, loop_device_5g, dm_name):
        luks1_format(loop_device_5g)
        backup = f"/tmp/luks1_backup_{rand_str(6)}"
        run_ok(f"cryptsetup luksHeaderBackup {loop_device_5g} --header-backup-file {backup} -q")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksRemoveKey -q {loop_device_5g}")
        rc, _ = run(f"echo -n '{PASSWD}' | cryptsetup open --test-passphrase -q {loop_device_5g}")
        assert rc != 0
        run_ok(f"cryptsetup luksHeaderRestore {loop_device_5g} --header-backup-file {backup} -q")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup open --test-passphrase -q {loop_device_5g}")
        os.remove(backup)

    def test_detached_header(self, loop_device_5g, header_file, dm_name):
        run_ok(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks1 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
            f"--header {header_file} -q {loop_device_5g}"
        )
        run_ok(
            f"echo -n '{PASSWD}' | cryptsetup luksOpen --header {header_file} "
            f"-q {loop_device_5g} {dm_name}"
        )
        luks_close(dm_name)

    def test_detached_header_offset_and_resize(self, loop_device_5g, header_file, dm_name):
        run_ok(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks1 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
            f"--header {header_file} --align-payload 8192 -q {loop_device_5g}"
        )
        run_ok(
            f"echo -n '{PASSWD}' | cryptsetup luksOpen --header {header_file} "
            f"-q {loop_device_5g} {dm_name}"
        )
        run_ok(f"cryptsetup -v status {dm_name}")
        run_ok(f"cryptsetup resize --header {header_file} -q --size 80 {dm_name}")
        run_ok(f"cryptsetup -v status {dm_name} | grep '80 sectors'")
        run_ok(f"cryptsetup luksSuspend --header {header_file} -q {dm_name}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksResume --header {header_file} -q {dm_name}")
        luks_close(dm_name)

    def test_detached_header_add_key_from_fake_device(self, loop_device_5g, header_file, keyfile_128):
        run_ok(
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks1 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
            f"--header {header_file} -q {loop_device_5g}"
        )
        run_ok(
            f"cryptsetup luksAddKey --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
            f"--key-slot 5 --header {header_file} "
            f"-q _fake_dev_ {keyfile_128}"
        )
        run_ok(f"cryptsetup luksDump --header {header_file} _fake_dev_ | "
               f"grep 'Key Slot 5: ENABLED'")
        run_ok(f"cryptsetup luksKillSlot --header {header_file} -q _fake_dev_ 5")
        run_ok(f"cryptsetup luksDump --header {header_file} _fake_dev_ | "
               f"grep 'Key Slot 5: DISABLED'")

    def test_detached_header_various_offsets(self, loop_device_5g, header_file, dm_name):
        base = (
            f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks1 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
            f"--header {header_file}"
        )
        run_fail(f"{base} --align-payload 1 -q {loop_device_5g}")
        run_ok(f"{base} --align-payload 8192 -q {loop_device_5g}")
        run_ok(f"{base} --align-payload 0 -q {loop_device_5g}")
        run_fail(f"{base} --align-payload 8192 --offset 8192 -q {loop_device_5g}")
        run_ok(f"{base} --key-slot 7 -q {loop_device_5g}")
        run_ok(f"{base} --offset 80000 -q {loop_device_5g}")
        run_ok(f"{base} --offset 8192 -q {loop_device_5g}")


class TestLUKS1KeyManagement:
    """LUKS1 key add, remove, change, kill slot operations."""

    def test_add_remove_key(self, loop_device_5g, dm_name):
        new_pass = rand_str(10)
        luks1_format(loop_device_5g)
        run_ok(f"echo -e '{PASSWD}\\n{new_pass}' | cryptsetup luksAddKey "
               f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 -q {loop_device_5g}")
        run_ok(f"echo -n '{new_pass}' | cryptsetup luksOpen -q {loop_device_5g} {dm_name}")
        luks_close(dm_name)
        run_ok(f"echo -n '{new_pass}' | cryptsetup luksRemoveKey -q {loop_device_5g}")
        rc, _ = run(f"echo -n '{PASSWD}' | cryptsetup open --test-passphrase -q {loop_device_5g}")
        assert rc != 0

    def test_change_key(self, loop_device_5g):
        new_pass = "compatkey"
        luks1_format(loop_device_5g)
        run_ok(f"echo -e '{PASSWD}\\n{new_pass}' | cryptsetup luksChangeKey "
               f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 -q {loop_device_5g}")
        rc, _ = run(f"echo -n '{PASSWD}' | cryptsetup open --test-passphrase -q {loop_device_5g}")
        assert rc != 0
        run_ok(f"echo -n '{new_pass}' | cryptsetup open --test-passphrase -q {loop_device_5g}")

    def test_kill_slot(self, loop_device_5g, dm_name):
        new_pass = rand_str(10)
        luks1_format(loop_device_5g)
        luks_add_key(loop_device_5g, old_pass=PASSWD, new_pass=new_pass,
                     pbkdf="pbkdf2", pbkdf_force_iterations=1000)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksKillSlot -q {loop_device_5g} 1")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {loop_device_5g} {dm_name}")
        luks_close(dm_name)
        rc, _ = run(f"echo -n '{new_pass}' | cryptsetup open --test-passphrase -q {loop_device_5g}")
        assert rc != 0

    def test_kill_slot_wrong_passwd_fails(self, loop_device_5g):
        luks1_format(loop_device_5g)
        run_fail(f"echo -n 'wrong_passwd' | cryptsetup luksKillSlot -q {loop_device_5g} 1")
        run_fail(f"cryptsetup luksKillSlot -q {loop_device_5g} 7")

    def test_kill_slot_nonexistent_fails(self, loop_device_5g):
        luks1_format(loop_device_5g)
        run_fail(f"echo -n '{PASSWD}' | cryptsetup luksKillSlot -q {loop_device_5g} 8")

    def test_keyfile_format_and_open(self, loop_device_5g, dm_name, keyfile_128):
        run_ok(f"cryptsetup luksFormat --type luks1 --pbkdf pbkdf2 "
               f"--pbkdf-force-iterations 1000 --key-file {keyfile_128} -q {loop_device_5g}")
        rc, _ = luks_open(loop_device_5g, dm_name, passwd="", spec=f"--key-file {keyfile_128}")
        assert rc
        luks_close(dm_name)

    def test_key_slot_specify(self, loop_device_5g, dm_name, keyfile_128):
        run_ok(f"cryptsetup luksFormat --type luks1 --pbkdf pbkdf2 "
               f"--pbkdf-force-iterations 1000 --key-slot 5 "
               f"--key-file {keyfile_128} -q {loop_device_5g}")
        run_fail(f"cryptsetup luksOpen --key-slot 4 --key-file {keyfile_128} "
                 f"-q {loop_device_5g} {dm_name}")
        run_ok(f"cryptsetup luksOpen --key-slot 5 --key-file {keyfile_128} "
               f"-q {loop_device_5g} {dm_name}")
        luks_close(dm_name)

    def test_add_key_to_specific_slot(self, loop_device_5g, dm_name, keyfile_128):
        run_ok(f"cryptsetup luksFormat --type luks1 --pbkdf pbkdf2 "
               f"--pbkdf-force-iterations 1000 --key-slot 5 "
               f"--key-file {keyfile_128} -q {loop_device_5g}")
        keyfile2 = make_keyfile(128)
        try:
            run_ok(f"cryptsetup luksAddKey --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
                   f"--key-slot 0 --key-file {keyfile_128} "
                   f"-q {loop_device_5g} {keyfile2}")
            run_ok(f"cryptsetup luksOpen --key-file {keyfile2} -q {loop_device_5g} {dm_name}")
            luks_close(dm_name)
        finally:
            if os.path.exists(keyfile2):
                os.remove(keyfile2)

    def test_two_passphrases_on_stdin(self, loop_device_5g, dm_name):
        new_pass = rand_str(10)
        run_ok(f"echo -n -e '{PASSWD}\\n{new_pass}' | cryptsetup --pbkdf pbkdf2 "
               f"--pbkdf-force-iterations 1000 -q --key-file=- "
               f"luksFormat --type luks1 {loop_device_5g}")
        run_ok(f"echo -n -e '{PASSWD}\\n{new_pass}' | cryptsetup -q --key-file=- "
               f"open {loop_device_5g} {dm_name}")
        luks_close(dm_name)


class TestLUKS1Stacked:
    """LUKS1 stacked device tests."""

    def test_luks_on_luks(self, loop_device_5g, dm_name):
        luks1_format(loop_device_5g)
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {loop_device_5g} {dm_name}")
        mapper = f"/dev/mapper/{dm_name}"
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks1 "
               f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 -q {mapper}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {mapper} dummy")
        luks_close("dummy")
        luks_close(dm_name)

    def test_dm_linear_luks(self, loop_device_5g, dm_name):
        run_ok(f"dmsetup create {dm_name} --table '0 40960 linear {loop_device_5g} 2'")
        mapper = f"/dev/mapper/{dm_name}"
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksFormat --type luks1 "
               f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 -q {mapper}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup luksOpen -q {mapper} dummy2")
        luks_close("dummy2")
        run_ok(f"dmsetup remove --retry {dm_name}")

    def test_plain_create_and_resize(self, loop_device_5g, dm_name):
        run_ok(f"cryptsetup create --hash sha256 --cipher aes-cbc-essiv:sha256 "
               f"--offset 8 --skip 4 -q --readonly {dm_name} {loop_device_5g}")
        run_ok(f"cryptsetup status {dm_name} | grep '8 sectors'")
        run_ok(f"cryptsetup status {dm_name} | grep '4 sectors'")
        run_ok(f"cryptsetup status {dm_name} | grep 'readonly'")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup resize --size 80 -q {dm_name}")
        run_ok(f"cryptsetup status {dm_name} | grep '80 sectors'")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup resize -q {dm_name}")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup resize --device-size 8M -q {dm_name}")
        run_ok(f"cryptsetup status {dm_name} | grep '16384 sectors'")
        run_ok(f"echo -n '{PASSWD}' | cryptsetup resize -q {dm_name}")
        run_ok(f"cryptsetup remove {dm_name}")


class TestLUKS1Repair:
    """LUKS1 header repair tests."""

    def test_repair_corrupted_header(self, loop_device_5g, dm_name, keyfile_128):
        run_ok(f"cryptsetup luksFormat --type luks1 --pbkdf pbkdf2 "
               f"--pbkdf-force-iterations 1000 --key-slot 0 "
               f"--key-file {keyfile_128} -q {loop_device_5g}")
        run_ok(f"dd if=/dev/urandom of={loop_device_5g} bs=512 seek=1 count=1")
        run_fail(f"cryptsetup luksOpen --key-file {keyfile_128} -q {loop_device_5g} {dm_name}")
        run_ok(f"cryptsetup repair -q {loop_device_5g}")
        run_ok(f"cryptsetup luksOpen --key-file {keyfile_128} -q {loop_device_5g} {dm_name}")
        luks_close(dm_name)

    def test_repair_corrupted_hash_spec(self, loop_device_5g, dm_name, keyfile_128):
        run_ok(f"cryptsetup luksFormat --type luks1 --pbkdf pbkdf2 "
               f"--pbkdf-force-iterations 1000 --hash sha256 --cipher aes-ecb "
               f"--key-file {keyfile_128} -q {loop_device_5g}")
        run_ok(f"echo -n 'SHA256' | dd of={loop_device_5g} bs=1 seek=72 >/dev/null 2>&1")
        run_ok(f"cryptsetup repair -q {loop_device_5g}")
        run_ok(f"cryptsetup luksOpen --key-file {keyfile_128} -q {loop_device_5g} {dm_name}")
        luks_close(dm_name)


class TestLUKS1Erase:
    """LUKS1 erase (wipe all keyslots)."""

    def test_erase_all_keys(self, loop_device_5g, keyfile_128):
        keyfile2 = make_keyfile(32)
        try:
            run_ok(f"cryptsetup luksFormat --type luks1 --pbkdf pbkdf2 "
                   f"--pbkdf-force-iterations 1000 --key-slot 5 "
                   f"--key-file {keyfile_128} -q {loop_device_5g}")
            run_ok(f"cryptsetup luksAddKey --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "
                   f"--key-slot 1 --key-file {keyfile_128} "
                   f"-q {loop_device_5g} {keyfile2}")
            run_ok(f"cryptsetup luksDump {loop_device_5g} | grep 'Key Slot 1: ENABLED'")
            run_ok(f"cryptsetup luksDump {loop_device_5g} | grep 'Key Slot 5: ENABLED'")
            run_ok(f"cryptsetup luksErase -q {loop_device_5g}")
            run_ok(f"cryptsetup luksDump {loop_device_5g} | grep 'Key Slot 5: DISABLED'")
            run_ok(f"cryptsetup luksDump {loop_device_5g} | grep 'Key Slot 1: DISABLED'")
        finally:
            if os.path.exists(keyfile2):
                os.remove(keyfile2)
