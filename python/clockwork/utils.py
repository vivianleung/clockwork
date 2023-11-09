from __future__ import annotations
import hashlib
import datetime
import logging
import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Sequence
from typing import Any

import pyfastaq


def decode(x: Any | bytes) -> Any | str:
    """Attempt to decode value, returning itself if cannot"""
    try:
        s = x.decode()
    except:
        return x
    return s


def syscall(command: str | Sequence, **run_kws) -> subprocess.CompletedProcess:
    """Run command via subprocess.run

    Parameters
    ---------
    command: str or list of arguments. Passed to subprocess.run
    **run_kws: Additonal kws to pass to subprocess.run. Defaults:
        - capture_output: True
        - text: True
        - check: True (to raise subprocess.CalledProcessError)

        .. version:
            (As of Python v3.7) 'text' is an alias of 'universal_newlines=True'
            with decoding. 'capture_output' is an 'alias' of 'stdout=PIPE' plus
            'stderr=PIPE'.

    Returns
    -------
    CompletedProcess
        The run process
    """
    logging.info("Run command: %s", str(command))
    if not run_kws.get("shell", False):

        if isinstance(command, str):
            cmd_args = shlex.split(command)
        else:
            cmd_args = [str(x) for x in command]

        # path of program. See python subprocess.Popen doc for details
        prog = shutil.which(cmd_args[0])
        
        if prog is None:
            logging.error("Program not found: %s", prog)
            raise ValueError(f"Program not found {prog}")
        
        cmd_args[0] = prog
    
        logging.debug("Program: %s", cmd_args[0])
    
    # set defaults
    run_kws = dict(capture_output=True, text=True, check=True) | run_kws

    try:
        proc = subprocess.run(cmd_args, **run_kws)

    except subprocess.CalledProcessError as error:

        print(
            f">>> Exited with code {error.returncode} for command {command}",
            *(f"stdout:  {s}" for s in '\n'.split(decode(proc.stdout))),
            *(f"stderr:  {s}" for s in '\n'.split(decode(proc.stderr))),
            sep="\n",
            file=sys.stderr,
        )
        logging.error("Return code: %d", error.returncode)
        raise error

    # success
    logging.info("stdout:\n%s", decode(proc.stdout))
    logging.info("stderr:\n%s", decode(proc.stderr))

    return proc


def md5(filename: str) -> str:
    """Given a file, returns a string that is the md5 sum of the file"""
    # see https://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def load_md5_from_file(filename: str) -> str:
    """Loads md5 from file, where could have been made my 'md5' on a mac,
    or 'md5sum' in linux. Assumes just one md5 in the file - only looks at
    the first line"""
    with open(filename) as f:
        line = f.readline().rstrip()

    # Mac:
    # MD5 (filename) = md5
    # Linux:
    # md5  filename
    try:
        if line.startswith("MD5"):
            md5sum = line.split()[-1]
        else:
            md5sum = line.split()[0]
    except:
        raise Exception("Error getting md5 from file " + filename + ". Unexpected format")

    if len(md5sum) != 32:
        raise Exception(
            "Error getting md5 from file " + filename + ". Expected string of length 32"
        )

    return md5sum


def rsync_and_md5(old_name: str, new_name: str, md5sum: str = None) -> str:
    """Copies a file from old_name to new_name using rsync.
    Double-checks the copy was successful using md5. Returns md5.
    If you already know the md5 of the file, then save time
    by providing it with the md5sum option - this will avoid
    calculating it on the old file."""
    if md5sum is None:
        md5sum = md5(old_name)

    syscall("rsync " + old_name + " " + new_name)
    new_md5sum = md5(new_name)

    if new_md5sum != md5sum:
        raise Exception(
            "Error copying file "
            + old_name
            + " -> "
            + new_name
            + "\n. md5s do not match"
        )
    else:
        return md5sum


def date_string_from_file_mtime(filename: str) -> str:
    """Returns a string in the form YYYYMMDD of the last modification
    date of a file"""
    try:
        mtime = os.path.getmtime(filename)
    except:
        raise Exception("Error getting modification time from file " + filename)

    d = datetime.datetime.fromtimestamp(mtime)
    return d.isoformat().split("T")[0].replace("-", "")


def make_empty_file(filename: str) -> None:
    """Makes empty file. Will overwrite if already exists"""
    with open(filename, "w"):
        pass


def sam_record_count(filename: str) -> int:
    """Returns number of sam records in file"""
    count = 0
    with open(filename) as f:
        for line in f:
            if not line.startswith("@"):
                count += 1
    return count


def vcf_has_records(filename: str) -> bool:
    """Returns true if there is at least 1 record in VCF file"""
    with open(filename) as f:
        for line in f:
            if not line.startswith("#"):
                return True
    return False


def file_has_at_least_one_line(filename: str) -> bool:
    """Returns true if there is at least 1 line in the file. Can be gzipped"""
    f = pyfastaq.utils.open_file_read(filename)
    has_line = any(f)
    f.close()
    return has_line
