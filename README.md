# luks_test - pytest-based LUKS/dm-crypt test suite

Pytest-based test suite for LUKS/dm-crypt/dm-integrity, rewritten from cryptsetup_libblockdev.

## Prerequisites
- cryptsetup >= 2.6
- integritysetup (optional, for dm-integrity tests)
- pytest >= 8.0
- Root access (loop devices, kernel modules)
- 20G free in /tmp (for loop backing files)

## Quick Start

```bash
# Run all tests:
sudo pytest -v

# Run only LUKS1 tests:
sudo pytest test_luks1.py -v

# Run only LUKS2 tests:
sudo pytest test_luks2.py -v

# Run only bug regression tests:
sudo pytest test_luks_bugs.py -v

# Skip slow tests (reencrypt with 10G loop):
sudo pytest -m "not slow" -v

# Run with specific markers:
sudo pytest -m "integrity" -v

# Run and stop on first failure:
sudo pytest -x -v
```

## Test Structure

| File | Purpose |
|------|--------|
| `test_luks1.py` | LUKS1 format, key management, header ops, repair, erase |
| `test_luks2.py` | LUKS2 format, PBKDF, resize, unbound keys, per-keyslot cipher, conversion |
| `test_luks_bugs.py` | Bug regression tests (bz1750680, bz2073433, bz2212771, bz2080516, etc.) |
| `test_integrity.py` | dm-integrity format, error detection, journal, modes, resize |
| `test_reencrypt.py` | LUKS re-encryption with header/data-shift/resilience modes (10G loop device) |
| `test_io_uring.py` | IO_uring filesystem stress tests |
| `conftest.py` | Shared fixtures (loop devices, keyfiles, headers)
| `helpers.py` | Shared utility functions |

## Fixture Hierarchy

- `loop_device_5g` (scope=module): 5G sparse loop device for general tests
- `loop_device_10g` (scope=module): 10G sparse loop device for reencrypt tests
- `keyfile_32/128/256/4096` (scope=function): Random keyfiles
- `header_file` (scope=function): 16M header file
- `dm_name` (scope=function): Random dm-crypt mapper name
