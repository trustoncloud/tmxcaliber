# tmxcaliber

This package is intended for `python3` and has been tested in `python3.8+`.

## Installation
Follow the instructions below to install the package on your operating system.

### Docker
Build the image and run the tool from the container as follows.
```sh
$: docker build -t tmxcaliber .
$: docker run --rm -it tmxcaliber [arg1] [arg2] ...

# example to get help doc
$: docker run --rm -it tmxcaliber -h
```

### Linux / MacOS
Initiate and activate virtual environment by running the following commands.
```sh
# python -m venv [path/to/virtual-env]
$: python -m venv .my-env
$: source .my-env/bin/activate
```
> **Note:** Virtual environment is used to isolate yourself from global installation of Python, enabling you to install packages of your desired versions. More details can be found [here](https://docs.python.org/3/library/venv.html).

Once the environment is activated, install the package via `pip` by running:
```sh
$: pip install git+ssh://git@github.com/trustoncloud/tmxcaliber.git
```

Alternatively, you can pull the repo first and then install:
```sh
$: git clone https://github.com/trustoncloud/tmxcaliber.git
$: cd tmxcaliber
$: pip install .
```

### Windows
First, initiate and activate the environment as follows.
```sh
# python -m venv [path/to/virtual-env]
$: python -m venv .my-env
$: .my-env\Scripts\activate.bat
```
Then, clone the git repository and install using `pip`.
```sh
$: git clone https://github.com/trustoncloud/tmxcaliber.git
$: cd tmxcaliber
$: pip install .
```

### Versioned Release
To install a specific release from git, you can take a look at all the available releases [here](../../releases). Then using `pip`, you install the version directly as follows.
```sh
$: pip install git+ssh://git@github.com/trustoncloud/tmxcaliber.git@{VERSION_TAG}
```
**`VERSION_TAG`** is the git tag associated with the release.

Alternatively, you can switch to a specific release after cloning the repository, and then install via `pip` as follows.
```sh
$: git clone https://github.com/trustoncloud/tmxcaliber.git tmxcaliber
$: cd tmxcaliber
$: git checkout tags/{VERSION_TAG}
$: pip install .
```
**`VERSION_TAG`** is the git tag associated with the release.

### Help Documentation
To get complete help on `tmxcaliber` command, run the following.
```sh
$: tmxcaliber -h

usage: tmxcaliber [-h] [-v] {filter,map,scan,generate,list} ...

options:
  -h, --help            show this help message and exit
  -v, --version         show the installed version.


operation:
  {filter,map,scan,generate,list}
    filter              filter down the ThreatModel data.
    map                 map ThreatModel data to OSCAL framework.
    scan                scan the ThreatModel data for a given pattern.
    generate            generate threat specific PNGs from XML data.
    list                List data of one or more ThreatModels.
```
You can also get more help on each operation:
```sh
# help for `filter` and `map` operations.
$: tmxcaliber filter -h
$: tmxcaliber map -h
```
## Usage
Details for supported operations, including the new list operations, are as follows:

### Filter

The `filter` operation allows you to filter relevant information from a ThreatModel JSON based on various criteria, such as feature class, threat severity, or IAM permission.
```sh
$: tmxcaliber filter path/to/threatmodel.json --severity high
```

### Map

The `map` operation allows you to map a ThreatModel control objectives to various frameworks/standards/regulations from the Secure Control Framework (SCF). The tool will execute and map every known control objective to SCF-supported frameworks.
```sh
$: tmxcaliber map path/to/threatmodel.json \
  --scf 2023.4 \
  --framework "ISO\n27001\nv2013" \
  --format csv
```

#### Map a framework not supported by the SCF
For non-supported frameworks, you must map your framework to the SCF. The format is a CSV mapping (see the template in the `template` folder). Once the mapping is done, you will be able to generate your mapping.
```sh
$: tmxcaliber map path/to/threatmodel.json \
  --scf 2023.4 \
  --framework path/to/myframework.csv \
  --format csv
```

### Scan
The `scan` opreation allows you to scan the description of all the controls for a given pattern. Support for currently known Amazon GuardDuty findings pattern has also been added.
```sh
$: tmxcaliber scan path/to/threatmodel.json --pattern regex_pattern|guardduty_findings
```

### Generate
The `generate` operation allows you to create threat focused and feature class focused XMLs and PNGs of the DFD. Input file here can be either a JSON file with XML inside `dfd.body` key as base64 encoded string or a XML file directly.
```sh
$: tmxcaliber generate path/to/threatmodel.json | path/to/dfd.xml \
  --threat-dir path/to/threats \
  --fc-dir path/to/features \
  --out-dir images/
```
Threats focused XMLs will be saved in `--threat-dir`  
Feature class focused XMLs will be saved in `--fc-dir`  
All the DFD images will be saved in `--out-dir`


### List Threats
The `list threats` operation allows you to list all threats from a ThreatModel JSON file or a directory containing multiple JSON files. You can also specify an output file to write the results in CSV format.

```sh
$: tmxcaliber list threats path/to/threatmodel.json
$: tmxcaliber list threats path/to/threatmodels/ --output threats.csv
```

### List Controls
The `list controls` operation allows you to list all controls from a ThreatModel JSON file or a directory containing multiple JSON files. You can also specify an output file to write the results in CSV format.

```sh
$: tmxcaliber list controls path/to/threatmodel.json
$: tmxcaliber list controls path/to/threatmodels/ --output controls.csv
```

## Contributing
If you'd like to contribute to the development of TMXcaliber, please submit a pull request or open an issue on the project's GitHub repository.
