# xcaliber

This package is intended for `python3` and has been tested in `python3.8+`.

## Installation
Follow the instructions below to install the package on your operating system.

### Linux / MacOS
Initiate and activate virtual environment by running the following commands.
```sh
python -m venv .venv
source .venv/bin/activate
```

Once the environment is activated, install the package via `pip` by running:
```sh
pip install git+ssh://git@github.com/trustoncloud/tmxcaliber.git
```

Alternatively, you can pull the repo first and then install:
```sh
git clone https://github.com/trustoncloud/tmxcaliber.git xcaliber
cd xcaliber
pip install .
```

### Windows
First, initiate and activate the environment as follows.
```sh
python -m venv .venv
.venv\Scripts\activate.bat
```
Then, clone the git repository and install using `pip`.
```sh
git clone https://github.com/trustoncloud/tmxcaliber.git xcaliber
cd xcaliber
pip install .
```

### Versioned Release
To install a specific release from git, you can take a look at all the available releases [here](../../releases). Then using `pip`, you install the version directly as follows.
```sh
pip install git+ssh://git@github.com/trustoncloud/tmxcaliber.git@{VERSION_TAG}
```
**`VERSION_TAG`** is the git tag associated with the release.

Alternatively, you can switch to a specific release after cloning the repository, and then install via `pip` as follows.
```sh
git clone https://github.com/trustoncloud/tmxcaliber.git xcaliber
cd xcaliber
git checkout tags/{VERSION_TAG}
pip install .
```
**`VERSION_TAG`** is the git tag associated with the release.

### Help Documentation
To get complete help on `xcaliber` command, run the following.
```sh
$: xcaliber -h

usage: xcaliber [-h] [-v] {filter,map} source

positional arguments:
  {filter,map}   Operation to apply on the ThreatModel JSON file.
  source         Path to ThreatModel JSON file.

options:
  -h, --help     show this help message and exit
  -v, --version  Show the installed version.
```
