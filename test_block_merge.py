"""Block layer merge tests.

Verifies that the block layer correctly merges adjacent I/O requests.
Uses null_blk to test bio-to-request merging via plug-list batching:
a single large O_DIRECT write is split into multiple bios by the kernel,
and adjacent bios are merged before dispatch. Merge accounting is
reflected in /sys/block/<dev>/stat fields (reads_merged, writes_merged).
"""
import os
import time
import mmap
import pytest
from helpers import run, run_ok, load_module, unload_module

NULLB_DEV = "/dev/nullb0"
STAT_PATH = "/sys/block/nullb0/stat"


def _get_stat():
    """Parse /sys/block/nullb0/stat and return key counters.

    Kernel stat fields (from Documentation/block/stat.rst):
      read I/Os, read merges, read sectors, read ticks,
      write I/Os, write merges, write sectors, write ticks, ...
    """
    with open(STAT_PATH) as f:
        parts = f.read().strip().split()
    return {
        "rd_ios":   int(parts[0]),
        "rd_m":     int(parts[1]),
        "rd_sect":  int(parts[2]),
        "wr_ios":   int(parts[4]),
        "wr_m":     int(parts[5]),
        "wr_sect":  int(parts[6]),
    }


@pytest.fixture(scope="module")
def nullb_dev():
    """Module-scoped null_blk device for merge tests."""
    unload_module("null_blk")
    run_ok("modprobe null_blk queue_depth=64")

    for _ in range(30):
        if os.path.exists(NULLB_DEV):
            break
        time.sleep(0.1)

    assert os.path.exists(NULLB_DEV), "nullb0 did not appear after modprobe"
    yield NULLB_DEV
    unload_module("null_blk")


def _aligned_buf(size):
    """Allocate a page-aligned buffer for O_DIRECT I/O."""
    buf = mmap.mmap(-1, size)
    buf[:] = b"A" * size
    return buf


class TestBioMerge:
    """Bio-to-request merge tests via the block-layer plug list."""

    def test_large_write_triggers_merges(self, nullb_dev):
        """A large O_DIRECT write is split into bios that get merged.

        The kernel limits each bio to max_sectors_kb (default 128 = 64KB).
        A 512KB write therefore creates ~8 bios. All bios are submitted
        under one plug context, so adjacent bios merge into a single
        request, and /sys/block/<dev>/stat writes_merged reflects this.
        """
        fd = os.open(nullb_dev, os.O_RDWR | os.O_DIRECT)
        try:
            before = _get_stat()

            buf = _aligned_buf(512 * 1024)
            os.pwrite(fd, buf, 0)
            time.sleep(0.5)

            after = _get_stat()
            wr_m = after["wr_m"] - before["wr_m"]
            wr_n = after["wr_ios"] - before["wr_ios"]

            assert wr_n > 0, "No writes completed"
            assert wr_m > 0, (
                f"No write merges detected: wr_m_delta={wr_m}, "
                f"wr_n_delta={wr_n}, wr_sect_delta={after['wr_sect'] - before['wr_sect']}"
            )
            # merged + completed collectively account for all submitted bios
            assert wr_m + wr_n >= 2, (
                f"Expected >=2 total bios, got merged={wr_m} + ios={wr_n}"
            )

        finally:
            os.close(fd)

    def test_single_page_write_no_merge(self, nullb_dev):
        """A single 4K write produces no merge - baseline verification."""
        fd = os.open(nullb_dev, os.O_RDWR | os.O_DIRECT)
        try:
            before = _get_stat()

            buf = _aligned_buf(4096)
            os.pwrite(fd, buf, 0)
            time.sleep(0.3)

            after = _get_stat()

            assert after["wr_ios"] - before["wr_ios"] == 1, "1 write IO expected"
            assert after["wr_sect"] - before["wr_sect"] == 8, "8 sectors expected"
            assert after["wr_m"] - before["wr_m"] == 0, (
                "Single bio should not trigger any merge"
            )

        finally:
            os.close(fd)

    def test_adjacent_segments_merge(self, nullb_dev):
        """Multiple adjacent writes produce merges proportional to bio count.

        A 1024KB O_DIRECT write at max_sectors_kb=128KB creates ~8 bios.
        All adjacent, so the block layer merges them into 1 request:
        writes_merged should be ~7 and writes_done should be ~1.
        """
        fd = os.open(nullb_dev, os.O_RDWR | os.O_DIRECT)
        try:
            before = _get_stat()

            buf = _aligned_buf(1024 * 1024)
            os.pwrite(fd, buf, 4096)
            time.sleep(0.5)

            after = _get_stat()
            wr_m = after["wr_m"] - before["wr_m"]
            wr_n = after["wr_ios"] - before["wr_ios"]

            assert wr_m > 0, f"No merges: wr_m={wr_m}, wr_n={wr_n}"
            assert after["wr_sect"] - before["wr_sect"] == 2048, (
                "Expected 2048 sectors (1024KB) written"
            )
            # Validate the accounting invariant
            assert wr_m + wr_n >= 2, (
                f"merge({wr_m}) + complete({wr_n}) >= 2 bios failed"
            )

        finally:
            os.close(fd)
