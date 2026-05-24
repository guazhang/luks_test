"""IO_uring tests — ported from io_uring.py."""
import os
import pytest
from helpers import run, run_ok


IO_URING_AVAILABLE = run(
    "grep -q 'CONFIG_IO_URING=y' /boot/config-$(uname -r)"
)[0] == 0

pytestmark = pytest.mark.skipif(
    not IO_URING_AVAILABLE,
    reason="Kernel CONFIG_IO_URING is not enabled"
)


def _liburing_installed():
    return (os.path.exists("/usr/lib64/liburing.so") or
            os.path.exists("/usr/lib/liburing.so") or
            run("pkg-config --exists liburing")[0] == 0 or
            os.path.isdir("/tmp/liburing"))


class TestIOUring:
    """IO_uring upstream tests on different filesystems."""

    @pytest.mark.skipif(not _liburing_installed(),
                        reason="liburing not installed")
    @pytest.mark.parametrize("fs", ["xfs", "ext4"])
    def test_io_uring_on_fs(self, loop_device_5g, fs):
        run_ok(f"mkfs.{fs} -f {loop_device_5g}")
        mount_point = "/tmp/pytest_uring_mnt"
        os.makedirs(mount_point, exist_ok=True)
        cur_dir = os.getcwd()
        try:
            run_ok(f"mount {loop_device_5g} {mount_point}")

            liburing_path = "/tmp/liburing"
            if not os.path.exists(liburing_path):
                rc, _ = run(f"git clone --depth 1 "
                           f"git://git.kernel.dk/liburing {liburing_path}")
                if rc != 0:
                    pytest.skip("Could not clone liburing repo")

            os.chdir(liburing_path)
            run_ok("./configure && make")
            rc, out = run("make runtests")
            assert rc == 0, f"liburing tests failed on {fs}: {out}"
        finally:
            os.chdir(cur_dir)
            run(f"umount {mount_point}", check=False)
            run(f"rm -rf {mount_point}", check=False)

    @pytest.mark.skipif(not _liburing_installed(),
                        reason="liburing not installed")
    def test_io_uring_on_device(self, loop_device_5g):
        run_ok(f"dd if=/dev/zero of=/home/test_uring.tar bs=1G count=10")
        cur_dir = os.getcwd()
        try:
            liburing_path = "/tmp/liburing"
            if not os.path.exists(liburing_path):
                rc, _ = run(f"git clone --depth 1 "
                           f"git://git.kernel.dk/liburing {liburing_path}")
                if rc != 0:
                    pytest.skip("Could not clone liburing")

            os.chdir(liburing_path)
            run_ok("./configure && make")

            with open("test/config.local", "w") as f:
                f.write(f"TEST_FILES='{loop_device_5g} /home/test_uring.tar'")

            rc, out = run("make runtests")
            assert rc == 0, f"liburing device tests failed: {out}"
        finally:
            os.chdir(cur_dir)
            if os.path.exists("/home/test_uring.tar"):
                os.remove("/home/test_uring.tar")

    def test_rhel_1346_no_timeout(self, loop_device_5g):
        before_out = run("dmesg | grep -c 'timed out' || echo 0",
                         capture=True)[1].strip()
        before = int(before_out) if before_out else 0

        after_out = run("dmesg | grep -c 'timed out' || echo 0",
                        capture=True)[1].strip()
        after = int(after_out) if after_out else 0

        assert after == before, \
            f"New block device timeouts detected: {after - before} new"
