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

## Usage

### Filter

The `filter` operation allows you to filter relevant information from a ThreatModel JSON based on various criteria, such as future class, threat severity, or IAM permission.

**Example:**

```sh
xcaliber filter path/to/threatmodel.json --severity high
```

### Map

The `map` operation allows you to map a ThreatModel control objectives to various frameworks/standards/regulations from the Secure Control Framework (SCF). In order to map, you need to download the OSCAL version of the SCF ([here](https://github.com/securecontrolsframework/scf-oscal-catalog-model/tree/main/SCF-OSCAL%20Releases), starting with 
JSON_Data_SCF) and choose one of the supported framework. The tool will execute and map every known control objective to SCF-supported frameworks.

**Example:**
```sh
xcaliber map path/to/threatmodel.json --scf path/to/oscal --framework "ISO\n27001\nv2013" --format csv
```

### Map a framework not supported by the SCF
For non-supported frameworks, you must map your framework to the SCF within the OSCAL JSON. Once the mapping is done, you will be able to generate your mapping.

**Example:**
```sh
xcaliber map path/to/threatmodel.json --scf path/to/oscal --framework "My Framework" --format csv
```

## Contributing

If you'd like to contribute to the development of TMXcaliber, please submit a pull request or open an issue on the project's GitHub repository.