"""BLKZEROOUT ioctl tests.

Verifies that BLKZEROOUT (0x127f) correctly zeroes a byte range on a
block device while preserving data outside the zeroed range.
"""
import os
import mmap
import array
import fcntl
import pytest
from helpers import run, run_ok, rand_str

# _IO(0x12, 127)
BLKZEROOUT = 0x127f


def _buf_aligned(size, byte=0):
    """Allocate a page-aligned mmap buffer, filled with *byte*."""
    b = mmap.mmap(-1, size)
    b[:] = bytes([byte]) * size
    return b


def _pread_exact(fd, size, offset):
    """Read *size* bytes at *offset* into a page-aligned buffer."""
    buf = mmap.mmap(-1, size)
    n = os.pread(fd, buf, offset)
    assert n == size, f"Short read: {n}/{size} at offset {offset}"
    return buf


def _pwrite_exact(fd, buf, offset):
    """Write *buf* at *offset*, assert all bytes written."""
    n = os.pwrite(fd, buf, offset)
    assert n == len(buf), f"Short write: {n}/{len(buf)} at offset {offset}"


@pytest.fixture(scope="module")
def loop_dev():
    """128MB loop device backed by a sparse file."""
    path = f"/tmp/pytest_blkzeroout_{rand_str(6)}.img"
    run_ok(f"truncate -s 128M {path}")
    dev = run_ok(f"losetup --show -f {path}").strip()
    run_ok("udevadm settle")
    yield dev
    run(f"losetup -d {dev}")
    if os.path.exists(path):
        os.remove(path)


class TestBLKZEROOUT:

    def test_zero_middle_range(self, loop_dev):
        """Zero the middle 64KB of a 128KB region, verify edges preserved."""
        fd = os.open(loop_dev, os.O_RDWR | os.O_DIRECT)
        try:
            # Write 0xAA pattern to 32 blocks (128KB)
            pat = _buf_aligned(4096, 0xAA)
            for i in range(32):
                _pwrite_exact(fd, pat, i * 4096)

            # BLKZEROOUT: zero blocks 8-24 (64KB range)
            zero_off = 8 * 4096
            zero_len = 16 * 4096
            range_ = array.array('Q', [zero_off, zero_len])
            fcntl.ioctl(fd, BLKZEROOUT, range_)

            # Verify zeroed range - byte-by-byte within one block
            zbuf = _pread_exact(fd, 4096, zero_off)
            assert zbuf[:] == b'\x00' * 4096, "First zeroed block not zero"
            zbuf = _pread_exact(fd, 4096, zero_off + zero_len - 4096)
            assert zbuf[:] == b'\x00' * 4096, "Last zeroed block not zero"

            # Data before zeroed range must be intact
            before = _pread_exact(fd, 4096, 0)
            assert before[:] == b'\xAA' * 4096, "Data before zero range corrupted"

            # Data after zeroed range must be intact
            after = _pread_exact(fd, 4096, (24 + 1) * 4096)
            assert after[:] == b'\xAA' * 4096, "Data after zero range corrupted"

            for b in [pat, zbuf, before, after]:
                b.close()
        finally:
            os.close(fd)

    def test_zero_single_block(self, loop_dev):
        """Zero a single 4K block."""
        fd = os.open(loop_dev, os.O_RDWR | os.O_DIRECT)
        try:
            pat = _buf_aligned(4096, 0xBB)
            _pwrite_exact(fd, pat, 0)
            _pwrite_exact(fd, pat, 4096)

            fcntl.ioctl(fd, BLKZEROOUT, array.array('Q', [0, 4096]))

            zbuf = _pread_exact(fd, 4096, 0)
            assert zbuf[:] == b'\x00' * 4096, "Block not zeroed"

            # Adjacent block untouched
            adj = _pread_exact(fd, 4096, 4096)
            assert adj[:] == b'\xBB' * 4096, "Adjacent block corrupted"

            for b in [pat, zbuf, adj]:
                b.close()
        finally:
            os.close(fd)

    def test_zero_range_overflow_fails(self, loop_dev):
        """start + len overflow uint64_t -> kernel returns -EINVAL."""
        fd = os.open(loop_dev, os.O_RDWR)
        try:
            # 0xFFFFFFFFFFFFF000 + 0x2000 = 0x10000000000000000 (overflow)
            with pytest.raises(OSError) as exc:
                fcntl.ioctl(fd, BLKZEROOUT,
                            array.array('Q', [0xFFFFFFFFFFFFF000, 0x2000]))
            assert exc.value.errno == 22  # EINVAL
        finally:
            os.close(fd)

    def test_zero_readonly_fails(self, loop_dev):
        """BLKZEROOUT on a read-only fd must fail with -EBADF."""
        fd = os.open(loop_dev, os.O_RDONLY)
        try:
            with pytest.raises(OSError) as exc:
                fcntl.ioctl(fd, BLKZEROOUT, array.array('Q', [0, 4096]))
            assert exc.value.errno == 9  # EBADF
        finally:
            os.close(fd)
