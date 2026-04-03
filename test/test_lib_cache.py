from pathlib import Path

from tmxcaliber.lib import cache as cache_module


def test_download_progress_bar_update_to_updates_total_and_progress():
    progress = cache_module.DownloadProgressBar(total=0, disable=True)
    try:
        deltas = []
        progress.update = lambda value: deltas.append(value)
        progress.update_to(b=2, bsize=5, tsize=20)
        assert progress.total == 20
        assert deltas == [10]
    finally:
        progress.close()


def test_download_file_streams_response_chunks_to_disk(tmp_path, monkeypatch):
    class FakeResponse:
        def __init__(self):
            self.headers = {"Content-Length": "5"}
            self._chunks = iter([b"abc", b"de", b""])

        def read(self, _size):
            return next(self._chunks)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    progress_events = []

    class FakeProgressBar:
        def __init__(self, **kwargs):
            progress_events.append(("init", kwargs))
            self.total = None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def update(self, value):
            progress_events.append(("update", value))

    monkeypatch.setattr(
        cache_module.urllib.request, "urlopen", lambda url: FakeResponse()
    )
    monkeypatch.setattr(cache_module, "DownloadProgressBar", FakeProgressBar)

    output = tmp_path / "download.bin"
    cache_module.download_file("https://example.com/file.bin", str(output))

    assert output.read_bytes() == b"abcde"
    assert progress_events[0][0] == "init"
    assert ("update", 3) in progress_events
    assert ("update", 2) in progress_events


def test_get_cached_local_path_for_downloads_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_module.tempfile, "gettempdir", lambda: str(tmp_path))
    calls = []

    def fake_download(url, output_path):
        calls.append((url, output_path))
        Path(output_path).write_text("cached", encoding="utf-8")

    monkeypatch.setattr(cache_module, "download_file", fake_download)

    result = cache_module.get_cached_local_path_for(
        "https://example.com/files/data.xlsx"
    )

    assert Path(result).read_text(encoding="utf-8") == "cached"
    assert calls == [
        (
            "https://example.com/files/data.xlsx",
            str(tmp_path / "tmx-caliber-cache" / "data.xlsx"),
        )
    ]


def test_get_cached_local_path_for_reuses_existing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_module.tempfile, "gettempdir", lambda: str(tmp_path))
    cache_dir = tmp_path / "tmx-caliber-cache"
    cache_dir.mkdir()
    cached_file = cache_dir / "data.xlsx"
    cached_file.write_text("existing", encoding="utf-8")

    monkeypatch.setattr(
        cache_module,
        "download_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected")),
    )

    result = cache_module.get_cached_local_path_for(
        "https://example.com/files/data.xlsx"
    )

    assert result == str(cached_file)
