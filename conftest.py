"""Shared pytest fixtures for cryptsetup tests."""
import os
import subprocess
import pytest
from helpers import run, run_ok, rand_str, make_keyfile, make_header, PASSWD


def _create_loop(size_gb=5):
    """Create a loop device backed by a sparse file. Returns (loop_dev, backing_file)."""
    file_path = f"/tmp/pytest_loop_{rand_str(6)}.img"
    run_ok(f"truncate -s {size_gb}G {file_path}")
    out = run_ok(f"losetup --show -f {file_path}")
    loop_dev = out.strip()
    run_ok("udevadm settle")
    return loop_dev, file_path


def _destroy_loop(loop_dev, file_path):
    """Teardown a loop device and remove its backing file."""
    run(f"losetup -d {loop_dev}")
    if os.path.exists(file_path):
        os.remove(file_path)


def _wipe_device(device):
    """Wipe filesystem signatures from a device."""
    run(f"wipefs -a {device}")
    run(f"dd if=/dev/zero of={device} bs=1M count=10", check=False)


@pytest.fixture(scope="module")
def loop_device_5g():
    """Module-scoped 5G loop device for general testing. Auto-cleaned up."""
    loop, backing = _create_loop(size_gb=5)
    _wipe_device(loop)
    yield loop
    subprocess.run("cryptsetup close --all", shell=True, capture_output=True)
    subprocess.run("dmsetup remove --all", shell=True, capture_output=True)
    _destroy_loop(loop, backing)


@pytest.fixture(scope="module")
def loop_device_10g():
    """Module-scoped 10G loop device for full-disk encryption tests."""
    loop, backing = _create_loop(size_gb=10)
    _wipe_device(loop)
    yield loop
    subprocess.run("cryptsetup close --all", shell=True, capture_output=True)
    subprocess.run("dmsetup remove --all", shell=True, capture_output=True)
    _destroy_loop(loop, backing)


@pytest.fixture
def keyfile_32():
    """32-byte keyfile, auto-cleaned."""
    path = make_keyfile(32)
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def keyfile_128():
    """128-byte keyfile, auto-cleaned."""
    path = make_keyfile(128)
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def keyfile_256():
    """256-byte keyfile, auto-cleaned."""
    path = make_keyfile(256)
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def keyfile_4096():
    """4096-byte keyfile, auto-cleaned."""
    path = make_keyfile(4096)
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def header_file():
    """16M header file, auto-cleaned."""
    path = make_header()
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def dm_name():
    """Generate a random dm-crypt mapper name."""
    return f"pytest_crypt_{rand_str(6)}"


@pytest.fixture(autouse=True)
def cleanup_devices():
    """Auto-cleanup: close all crypt devices after each test."""
    yield
    subprocess.run("cryptsetup close --all", shell=True, capture_output=True)
    subprocess.run("dmsetup remove --all", shell=True, capture_output=True)
