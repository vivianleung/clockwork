from collections.abc import Sequence

from clockwork import utils

def validate(filenames: Sequence[str]) -> None:
    assert 1 <= len(filenames) <= 2
    cmd = "fqtools validate " + " ".join(filenames)
    try:
        utils.syscall(cmd)
    except:
        raise Exception("Error running " + cmd)


def count(filenames: Sequence[str]) -> int:
    assert 1 <= len(filenames) <= 2, \
        f"Need 1 or 2 files, but {len(filenames)} given: {filenames}"
    
    cmd = ["fqtools", "count", *filenames]
    # cmd = "fqtools count " + " ".join(filenames)
    try:
        completed_process = utils.syscall(cmd)
    except Exception as error:
        raise Exception(f"Error running {cmd}") from error

    try:
        read_count = int(completed_process.stdout.rstrip())
    except Exception as error:
        raise Exception(f'Error getting read count from: "{completed_process.stdout}"') from error

    return read_count
