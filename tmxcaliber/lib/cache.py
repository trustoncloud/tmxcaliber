import os
import tempfile
import urllib.request
from tqdm import tqdm

def download_file(url, output_path):
    with urllib.request.urlopen(url) as response, open(output_path, 'wb') as out_file, DownloadProgressBar(unit='B', unit_scale=True, miniters=1, desc=url.split('/')[-1]) as t:
        file_size = int(response.headers['Content-Length'])
        t.total = file_size
        for chunk in iter(lambda: response.read(4096), b''):
            out_file.write(chunk)
            t.update(len(chunk))

class DownloadProgressBar(tqdm):
    def update_to(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)

def get_cached_local_path_for(file_url):
    # Determine cache directory path
    cache_dir = os.path.join(tempfile.gettempdir(), 'tmx-caliber-cache')
    # Ensure cache directory exists
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    
    # Determine the filename from the URL and create its path in the cache directory
    file_name = file_url.split('/')[-1]
    cached_file_path = os.path.join(cache_dir, file_name)
    
    # Check if the file is already downloaded, if not, download it
    if not os.path.exists(cached_file_path):
        print("Downloading file...")
        download_file(file_url, cached_file_path)
    return cached_file_path