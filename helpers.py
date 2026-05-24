"""Shared utilities for cryptsetup pytest tests."""
import subprocess
import random
import string
import os
import json

PASSWD = "passwdpasswd"


def run(cmd, check=False, capture=True):
    """Run a shell command. Returns (returncode, stdout_str)."""
    result = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if capture:
        return result.returncode, result.stdout.strip()
    return result.returncode, ""


def run_ok(cmd, msg=None):
    """Run a command and assert it succeeds. Returns stripped stdout."""
    rc, out = run(cmd)
    if msg is None:
        msg = f"Command failed [{rc}]: {cmd}\n{out}"
    assert rc == 0, msg
    return out


def run_fail(cmd, msg=None):
    """Run a command and assert it fails. Returns stripped stdout."""
    rc, out = run(cmd)
    if msg is None:
        msg = f"Command should have failed but succeeded: {cmd}"
    assert rc != 0, msg
    return out


def rand_str(n=8):
    """Generate a random alphanumeric string."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


def make_keyfile(size=32, path=None):
    """Create a keyfile with random content, return its path."""
    if path is None:
        path = f"/tmp/pytest_keyfile_{rand_str(6)}"
    data = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
    with open(path, "w") as f:
        f.write(data)
    return path


def make_header(path=None):
    """Create a 16M LUKS header file, return its path."""
    if path is None:
        path = f"/tmp/pytest_header_{rand_str(6)}"
    run_ok(f"truncate -s 16M {path}")
    return path


def luks_dump(device, header=None):
    """Run cryptsetup luksDump and return parsed JSON."""
    hdr = f" --header {header}" if header else ""
    out = run_ok(f"cryptsetup luksDump --dump-json-metadata {hdr} {device}")
    return json.loads(out)


def luks_status(name):
    """Run cryptsetup status and return parsed dict."""
    out = run_ok(f"cryptsetup status {name}")
    status = {}
    for line in out.split("\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            status[k.strip()] = v.strip()
    return status


def luks_format(device, luks_type="luks2", cipher="aes-xts-plain64",
                key_size=256, pbkdf="pbkdf2", iter_time=1000, **extra):
    """Format a device as LUKS, return (success_bool, stdout)."""
    opts = []
    for k, v in extra.items():
        if v:
            opts.append(f"--{k.replace('_', '-')} {v}")
    cmd = (
        f"echo -n '{PASSWD}' | cryptsetup luksFormat --type {luks_type} "
        f"--cipher {cipher} --key-size {key_size} "
        f"--pbkdf {pbkdf} --iter-time {iter_time} "
        f"{' '.join(opts)} -q {device}"
    )
    rc, out = run(cmd)
    return rc == 0, out


def luks_open(device, name, passwd=PASSWD, header=None, spec="", set_passwd=True):
    """Open a LUKS device, return (success_bool, stdout)."""
    hdr = f" --header {header}" if header else ""
    if set_passwd and passwd:
        cmd = f"echo -n '{passwd}' | cryptsetup luksOpen {hdr} {spec} {device} {name}"
    elif spec:
        cmd = f"cryptsetup luksOpen {hdr} {spec} {device} {name}"
    else:
        cmd = f"cryptsetup luksOpen {hdr} -q {device} {name}"
    rc, out = run(cmd)
    return rc == 0, out


def luks_close(name):
    """Close a LUKS device."""
    run_ok(f"cryptsetup luksClose {name}")


def luks_add_key(device, old_pass=PASSWD, new_pass=None, key_file=None, **extra):
    """Add a key to a LUKS device. Returns (success_bool, stdout)."""
    opts = " ".join(f"--{k.replace('_', '-')} {v}" for k, v in extra.items() if v)
    new_key = new_pass or PASSWD
    cmd = (
        f"echo -e '{old_pass}\\n{new_key}' | "
        f"cryptsetup luksAddKey {opts} -q {device}"
    )
    rc, out = run(cmd)
    return rc == 0, out


def load_module(name):
    """Load a kernel module."""
    run_ok(f"modprobe {name}")


def unload_module(name):
    """Unload a kernel module if loaded."""
    run(f"modprobe -r {name}")


def check_cmd_opt(cmd, opt):
    """Check if a command supports a given option."""
    rc, _ = run(f"{cmd} --help | grep -q '{opt}'")
    return rc == 0


def system(cmd):
    """Run a command without capturing output (for visibility)."""
    return subprocess.run(cmd, shell=True).returncode
