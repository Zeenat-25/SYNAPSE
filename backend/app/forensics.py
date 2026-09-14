import hashlib
import math
from collections import Counter
from pathlib import Path


CHUNK_SIZE = 1024 * 1024


def calculate_hashes(
    file_path: Path,
) -> dict[str, str]:

    sha256_hash = hashlib.sha256()
    sha1_hash = hashlib.sha1()
    md5_hash = hashlib.md5()

    with file_path.open("rb") as file:

        while True:

            chunk = file.read(
                CHUNK_SIZE
            )

            if not chunk:
                break

            sha256_hash.update(chunk)
            sha1_hash.update(chunk)
            md5_hash.update(chunk)

    return {
        "sha256": sha256_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "md5": md5_hash.hexdigest(),
    }


def calculate_entropy(
    file_path: Path,
) -> float:

    frequencies: Counter[int] = Counter()

    total_bytes = 0

    with file_path.open("rb") as file:

        while True:

            chunk = file.read(
                CHUNK_SIZE
            )

            if not chunk:
                break

            frequencies.update(chunk)
            total_bytes += len(chunk)


    if total_bytes == 0:
        return 0.0


    entropy = 0.0

    for count in frequencies.values():

        probability = (
            count / total_bytes
        )

        entropy -= (
            probability
            * math.log2(
                probability
            )
        )


    return round(
        entropy,
        4,
    )


def get_extension(
    filename: str,
) -> str:

    suffix = (
        Path(filename)
        .suffix
        .lower()
    )

    if not suffix:
        return "none"

    return suffix