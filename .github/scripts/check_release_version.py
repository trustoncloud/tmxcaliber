import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

import tomllib


def main() -> int:
    pyproject = tomllib.loads(pathlib.Path("pyproject.toml").read_text())
    current_version = str(pyproject["project"]["version"])

    request = urllib.request.Request(
        f"https://api.github.com/repos/{os.environ['GITHUB_REPOSITORY']}"
        "/releases/latest",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )

    try:
        with urllib.request.urlopen(request) as response:
            latest_tag = json.load(response)["tag_name"]
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print("No GitHub release found yet, skipping version comparison.")
            return 0
        raise

    latest_version = latest_tag.split("-", 1)[0]

    if current_version == latest_version:
        print(
            f"Version {current_version} matches the latest GitHub release base "
            f"version ({latest_tag})."
        )
        print("Bump pyproject.toml [project].version before merging or releasing.")
        return 1

    print(
        f"Version check passed: {current_version} differs from latest release "
        f"base version {latest_version}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
