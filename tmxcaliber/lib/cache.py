import os
import tempfile
import urllib.request
from typing import TYPE_CHECKING

from tqdm import tqdm

if TYPE_CHECKING:
    _ProgressBase = tqdm[int]
else:
    _ProgressBase = tqdm


class DownloadProgressBar(_ProgressBase):
    def update_to(self, b: int = 1, bsize: int = 1, tsize: int | None = None) -> None:
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)


def download_file(url: str, output_path: str) -> None:
    with (
        urllib.request.urlopen(url) as response,
        open(output_path, "wb") as out_file,
        DownloadProgressBar(
            unit="B", unit_scale=True, miniters=1, desc=url.split("/")[-1]
        ) as t,
    ):
        file_size = int(response.headers["Content-Length"])
        t.total = file_size
        for chunk in iter(lambda: response.read(4096), b""):
            out_file.write(chunk)
            t.update(len(chunk))


def get_cached_local_path_for(file_url: str) -> str:
    # Determine cache directory path
    cache_dir = os.path.join(tempfile.gettempdir(), "tmx-caliber-cache")
    # Ensure cache directory exists
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)

    # Determine the filename from the URL and create its path in the cache directory
    file_name = file_url.split("/")[-1]
    cached_file_path = os.path.join(cache_dir, file_name)

    # Check if the file is already downloaded, if not, download it
    if not os.path.exists(cached_file_path):
        print("Downloading file...")
        download_file(file_url, cached_file_path)
    return cached_file_path
