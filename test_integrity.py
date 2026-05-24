"""dm-integrity tests — ported from luks_validation.py."""
import os
import pytest
from helpers import (
    run, run_ok, run_fail, rand_str, make_keyfile,
    PASSWD, load_module, check_cmd_opt,
)


pytestmark = pytest.mark.skipif(
    run("which integritysetup")[0] != 0,
    reason="integritysetup not installed"
)


def check_integrity_feature(feature):
    """Check dm-integrity version for a specific feature."""
    rc, ver_str = run("dmsetup targets | grep integrity | cut -f2 -dv", capture=True)
    if rc != 0:
        return False
    ver = ver_str.split(".")
    ver_maj = int(ver[0])
    ver_min = int(ver[1])
    features = []
    if ver_maj >= 1 and ver_min > 1:
        features.append("DM_INTEGRITY_META")
        features.append("DM_INTEGRITY_RECALC")
    if ver_maj >= 1 and ver_min > 2:
        features.append("DM_INTEGRITY_BITMAP")
    if ver_maj >= 1 and ver_min > 5 and not check_cmd_opt("integritysetup", "resize"):
        features.append("DM_INTEGRITY_RESIZE_SUPPORTED")
    if ver_maj >= 1 and ver_min > 6:
        features.append("DM_INTEGRITY_HMAC_FIX")
    return feature in features


class TestIntegrityFormat:
    """dm-integrity format and open tests."""

    @pytest.mark.parametrize("alg,tag_size,check_tag_size,sector,keyfile_ref,key_size", [
        ("sha256", 0, 32, 512, None, None),
        ("sha256", 0, 32, 4096, None, None),
        ("hmac-sha256", 0, 32, 512, "keyfile_32", 32),
        ("hmac-sha256", 0, 32, 4096, "keyfile_32", 32),
        ("hmac-sha256", 0, 32, 4096, "keyfile_4096", 4096),
    ])
    def test_format_open_checksum(self, loop_device_5g, dm_name,
                                    alg, tag_size, check_tag_size, sector,
                                    keyfile_ref, key_size, request):
        load_module("dm-integrity")

        key_file = None
        if keyfile_ref:
            key_file = request.getfixturevalue(keyfile_ref)

        key_opts = ""
        if key_file and key_size:
            key_opts = f"--integrity-key-file {key_file} --integrity-key-size {key_size}"

        tag_opt = f"--tag-size {tag_size}" if tag_size != 0 else ""
        run_ok(f"integritysetup format --integrity {alg} {tag_opt} "
               f"--sector-size {sector} {key_opts} "
               f"--integrity-legacy-padding -q {loop_device_5g}")

        run_ok(f"integritysetup dump {loop_device_5g} | "
               f"grep 'tag_size {check_tag_size}'")
        run_ok(f"integritysetup dump {loop_device_5g} | "
               f"grep 'sector_size {sector}'")

        run_ok(f"integritysetup open --integrity {alg} {key_opts} "
               f"-q {loop_device_5g} {dm_name}")
        mapper = f"/dev/mapper/{dm_name}"
        vsum1 = run_ok(f"sha256sum {mapper}")[:64]

        run_ok(f"dd if=/dev/zero of={mapper} bs=1M oflag=direct 2>/dev/null")
        run_ok(f"dmsetup remove --retry {dm_name}")

        run_ok(f"integritysetup open --integrity {alg} {key_opts} "
               f"-q {loop_device_5g} {dm_name}")
        vsum2 = run_ok(f"sha256sum {mapper}")[:64]

        assert vsum1 == vsum2, "Checksum mismatch after re-open"
        run_ok(f"integritysetup close {dm_name}")


class TestIntegrityErrorDetection:
    """dm-integrity error detection tests."""

    @pytest.mark.parametrize("alg,mode,tag_size,sector,keyfile_ref,key_size", [
        ("crc32c", "J", 0, 512, None, None),
        ("crc32c", "J", 0, 4096, None, None),
        ("sha1", "J", 0, 512, None, None),
        ("sha1", "J", 0, 4096, None, None),
        ("sha256", "J", 0, 512, None, None),
        ("sha256", "J", 0, 4096, None, None),
        ("hmac-sha256", "J", 0, 512, "keyfile_32", 32),
        ("hmac-sha256", "J", 0, 4096, "keyfile_32", 32),
    ])
    def test_error_detection(self, loop_device_5g, dm_name,
                              alg, mode, tag_size, sector,
                              keyfile_ref, key_size, request):
        load_module("dm-integrity")

        key_file = None
        if keyfile_ref:
            key_file = request.getfixturevalue(keyfile_ref)

        int_mode_flag = "-B" if mode == "B" else ""
        key_opts = ""
        if key_file and key_size:
            key_opts = f"--integrity-key-file {key_file} --integrity-key-size {key_size}"

        run_ok(f"dd if=/dev/zero of={loop_device_5g} bs=1M count=32")
        tag_opt = f"--tag-size {tag_size}" if tag_size != 0 else ""

        run_ok(f"integritysetup format {int_mode_flag} -q "
               f"--integrity {alg} {tag_opt} --sector-size {sector} "
               f"{key_opts} {loop_device_5g}")

        run_ok(f"integritysetup open --integrity {alg} {key_opts} "
               f"--integrity-no-journal {int_mode_flag} -q "
               f"{loop_device_5g} {dm_name}")

        if key_file and key_size:
            rc, key_hex = run(f"xxd -c 256 -l {key_size} -p {key_file}", capture=True)
            if rc == 0 and key_hex:
                run_ok(f"dmsetup table --showkeys {dm_name} | grep -q '{key_hex}'")

        mapper = f"/dev/mapper/{dm_name}"
        write_code = "EXAMPLETEXT"
        run_ok(f"echo -n {write_code} | dd of={mapper} 2>/dev/null")
        run_ok(f"integritysetup close {dm_name}")

        out = run_ok(f"dd if={loop_device_5g} bs=512 2>/dev/null | "
                     f"hexdump -C | grep {write_code}")
        off_dex = int(out.split()[0], 16)

        run_ok(f"echo -n Z | dd of={loop_device_5g} bs=1 seek={off_dex} "
               f"conv=notrunc 2>/dev/null")

        run_ok(f"integritysetup open --integrity {alg} {key_opts} "
               f"--integrity-no-journal {int_mode_flag} -q "
               f"{loop_device_5g} {dm_name}")
        rc, _ = run(f"dd if={mapper} of=/dev/null bs=512 2>&1")
        assert rc != 0, f"Expected I/O error on corrupted data, got rc={rc}"
        run_ok(f"integritysetup close {dm_name}")


class TestIntegrityJournal:
    """dm-integrity journal tests."""

    @pytest.mark.parametrize("alg,tag_size,sector,watermark,commit_time", [
        ("crc32", 4, 512, 66, 1000),
        ("sha256", 32, 4096, 34, 5000),
        ("sha1", 20, 512, 75, 9999),
    ])
    def test_journal_params(self, loop_device_5g, dm_name, keyfile_4096,
                             alg, tag_size, sector, watermark, commit_time):
        load_module("dm-integrity")

        run_ok(f"integritysetup format --integrity {alg} --tag-size {tag_size} "
               f"--sector-size {sector} --journal-watermark {watermark} "
               f"--journal-commit-time {commit_time} "
               f"--journal-integrity hmac-sha256 "
               f"--journal-integrity-key-file {keyfile_4096} "
               f"--journal-integrity-key-size 32 "
               f"-q {loop_device_5g}")

        run_ok(f"integritysetup open --integrity {alg} "
               f"--journal-watermark {watermark} "
               f"--journal-commit-time {commit_time} "
               f"--journal-integrity hmac-sha256 "
               f"--journal-integrity-key-file {keyfile_4096} "
               f"--journal-integrity-key-size 32 "
               f"-q {loop_device_5g} {dm_name}")

        rc, key_hex = run(f"xxd -c 4096 -l 32 -p {keyfile_4096}", capture=True)
        if rc == 0 and key_hex:
            run_ok(f"dmsetup table --showkeys {dm_name} | grep -q '{key_hex}'")

        run_ok(f"integritysetup close {dm_name}")


class TestIntegrityJournalCrypt:
    """dm-integrity journal encryption tests."""

    @pytest.mark.parametrize("crypt_alg,crypt_alg_kernel,key_size", [
        ("cbc-aes", "cbc(aes)", 32),
        ("ctr-aes", "ctr(aes)", 32),
    ])
    def test_journal_crypt(self, loop_device_5g, dm_name, keyfile_4096,
                            crypt_alg, crypt_alg_kernel, key_size):
        load_module("dm-integrity")

        run_ok(f"integritysetup format --journal-crypt {crypt_alg} "
               f"--journal-crypt-key-file {keyfile_4096} "
               f"--journal-crypt-key-size {key_size} "
               f"-q {loop_device_5g}")

        run_ok(f"integritysetup open --journal-crypt {crypt_alg} "
               f"--journal-crypt-key-file {keyfile_4096} "
               f"--journal-crypt-key-size {key_size} "
               f"-q {loop_device_5g} {dm_name}")

        rc, key_hex = run(f"xxd -c 256 -l {key_size} -p {keyfile_4096}", capture=True)
        if rc == 0 and key_hex:
            run_ok(f"dmsetup table --showkeys {dm_name} | "
                   f"grep -q '{crypt_alg_kernel}:{key_hex}'")

        run_ok(f"integritysetup close {dm_name}")


class TestIntegrityModes:
    """dm-integrity journal/bitmap/direct/recovery mode tests."""

    @pytest.mark.parametrize("alg,tag_size,sector,keyfile_ref,key_size", [
        ("crc32c", 4, 512, None, None),
        ("sha256", 32, 512, None, None),
        ("hmac-sha256", 32, 512, "keyfile_32", 32),
    ])
    def test_integrity_modes(self, loop_device_5g, dm_name, request,
                              alg, tag_size, sector, keyfile_ref, key_size):
        load_module("dm-integrity")

        key_file = None
        if keyfile_ref:
            key_file = request.getfixturevalue(keyfile_ref)

        key_opts = ""
        if key_file and key_size:
            key_opts = f"--integrity-key-file {key_file} --integrity-key-size {key_size}"

        tag_opt = f"--tag-size {tag_size}" if tag_size else ""
        run_ok(f"integritysetup format --integrity {alg} {tag_opt} "
               f"--sector-size {sector} {key_opts} -q {loop_device_5g}")

        # J mode (journal)
        run_ok(f"integritysetup open --integrity {alg} {key_opts} "
               f"-q {loop_device_5g} {dm_name}")
        out = run_ok(f"dmsetup table --showkeys {dm_name}")
        assert out.split()[6] == "J", f"Expected J mode, got: {out.split()[:10]}"
        run_ok(f"integritysetup close {dm_name}")

        # D mode (direct/no-journal)
        run_ok(f"integritysetup open --integrity {alg} {key_opts} "
               f"--integrity-no-journal -q {loop_device_5g} {dm_name}")
        out = run_ok(f"dmsetup table --showkeys {dm_name}")
        assert out.split()[6] == "D", f"Expected D mode, got: {out.split()[:10]}"
        run_ok(f"integritysetup close {dm_name}")

        # R mode (recovery)
        run_ok(f"integritysetup open --integrity {alg} {key_opts} "
               f"--integrity-recovery-mode -q {loop_device_5g} {dm_name}")
        out = run_ok(f"dmsetup table --showkeys {dm_name}")
        assert out.split()[6] == "R", f"Expected R mode, got: {out.split()[:10]}"
        run_ok(f"integritysetup close {dm_name}")


class TestIntegrityFeature:
    """dm-integrity advanced feature tests."""

    def test_recalculate(self, loop_device_5g, dm_name):
        load_module("dm-integrity")
        if not check_integrity_feature("DM_INTEGRITY_RECALC"):
            pytest.skip("DM_INTEGRITY_RECALC not supported")

        run_ok(f"integritysetup format --no-wipe -q {loop_device_5g}")
        run_ok(f"integritysetup open --integrity-recalculate -q {loop_device_5g} {dm_name}")
        mapper = f"/dev/mapper/{dm_name}"
        vsum1 = run_ok(f"sha256sum {mapper}")[:64]
        run_ok(f"dd if={mapper} of=/dev/null bs=1M 2>/dev/null")
        vsum2 = run_ok(f"sha256sum {mapper}")[:64]
        assert vsum1 == vsum2, "Checksum changed after recalculate"
        run_ok(f"integritysetup close {dm_name}")

    def test_bitmap_mode(self, loop_device_5g, dm_name):
        load_module("dm-integrity")
        if not check_integrity_feature("DM_INTEGRITY_BITMAP"):
            pytest.skip("DM_INTEGRITY_BITMAP not supported")

        run_ok(f"integritysetup format --integrity-bitmap-mode "
               f"-q {loop_device_5g}")
        run_ok(f"integritysetup open --integrity-bitmap-mode "
               f"--bitmap-sectors-per-bit 65536 --bitmap-flush-time 5000 "
               f"-q {loop_device_5g} {dm_name}")
        run_ok(f"integritysetup status {dm_name} | "
               f"grep 'bitmap 512-byte sectors per bit: 65536'")
        run_ok(f"integritysetup status {dm_name} | "
               f"grep 'bitmap flush interval: 5000 ms'")
        run_ok(f"integritysetup close {dm_name}")

    def test_legacy_hmac(self, loop_device_5g, dm_name, keyfile_32, keyfile_4096):
        load_module("dm-integrity")
        if not check_integrity_feature("DM_INTEGRITY_HMAC_FIX"):
            pytest.skip("DM_INTEGRITY_HMAC_FIX not supported")

        run_ok(f"integritysetup format --integrity-legacy-hmac --no-wipe "
               f"--tag-size 32 --integrity hmac-sha256 "
               f"--integrity-key-file {keyfile_4096} --integrity-key-size 32 "
               f"-q {loop_device_5g}")

        run_fail(f"integritysetup open --integrity-recalculate "
                 f"--integrity hmac-sha256 "
                 f"--integrity-key-file {keyfile_4096} --integrity-key-size 32 "
                 f"-q {loop_device_5g} {dm_name}")

        run_ok(f"integritysetup open --integrity-legacy-recalculate "
               f"--integrity hmac-sha256 "
               f"--integrity-key-file {keyfile_4096} --integrity-key-size 32 "
               f"-q {loop_device_5g} {dm_name}")
        run_ok(f"integritysetup close {dm_name}")


class TestIntegrityResize:
    """dm-integrity resize tests."""

    @pytest.mark.skipif(not check_cmd_opt("integritysetup", "resize"),
                        reason="integritysetup resize not supported")
    def test_resize(self, loop_device_5g, dm_name):
        load_module("dm-integrity")
        if not check_integrity_feature("DM_INTEGRITY_RESIZE_SUPPORTED"):
            pytest.skip("DM_INTEGRITY_RESIZE_SUPPORTED not detected")

        run_ok(f"integritysetup format --integrity crc32 -q {loop_device_5g}")
        run_ok(f"integritysetup open --integrity crc32 -q {loop_device_5g} {dm_name}")
        mapper = f"/dev/mapper/{dm_name}"
        run_ok(f"integritysetup resize --device-size 1MiB -q {mapper}")
        run_ok(f"dd if={mapper} of=/dev/null bs=512 count=1 2>/dev/null")
        run_ok(f"integritysetup resize -q {mapper}")
        run_ok(f"integritysetup close {dm_name}")
