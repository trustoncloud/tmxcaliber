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
$: python -m venv .venv
$: source .venv/bin/activate
```

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
$: python -m venv .venv
$: .venv\Scripts\activate.bat
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

usage: tmxcaliber [-h] [-v] {filter,map,scan,generate} ...

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show the installed version.


operation:
  {filter,map,scan,generate}
    filter              filter down the threat model data.
    map                 map threat model data to OSCAL framework.
    scan                scan threat model data against patterns.
    generate            generate threat specific PNGs from XML data.
```
You can also get more help on each operation:
```sh
# help for `filter` and `map` operations.
$: tmxcaliber filter -h
$: tmxcaliber map -h
```
## Usage
Details for supported 
### Filter

The `filter` operation allows you to filter relevant information from a ThreatModel JSON based on various criteria, such as feature class, threat severity, or IAM permission.
```sh
$: tmxcaliber filter path/to/threatmodel.json --severity high
```

### Map

The `map` operation allows you to map a ThreatModel control objectives to various frameworks/standards/regulations from the Secure Control Framework (SCF). In order to map, you need to download the OSCAL version of the SCF ([here](https://github.com/securecontrolsframework/scf-oscal-catalog-model/tree/main/SCF-OSCAL%20Releases), starting with 
JSON_Data_SCF) and choose one of the supported framework. The tool will execute and map every known control objective to SCF-supported frameworks.
```sh
$: tmxcaliber map path/to/threatmodel.json \
  --scf path/to/oscal.json \
  --framework "ISO\n27001\nv2013" \
  --format csv
```

### Map a framework not supported by the SCF
For non-supported frameworks, you must map your framework to the SCF within the OSCAL JSON. Once the mapping is done, you will be able to generate your mapping.
```sh
$: tmxcaliber map path/to/threatmodel.json \
  --scf path/to/oscal.json \
  --framework "My Framework" \
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

## Contributing

If you'd like to contribute to the development of TMXcaliber, please submit a pull request or open an issue on the project's GitHub repository.
