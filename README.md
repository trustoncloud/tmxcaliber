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
$: tmxcaliber list threats --help
usage: tmxcaliber list threats [-h] [--output OUTPUT]
                               [--severity {very high,high,medium,low,very low}]
                               [--feature-classes FEATURE_CLASSES]
                               source

positional arguments:
  source                Path to the ThreatModel JSON file or directory containing ThreatModel JSON files.

options:
  -h, --help            show this help message and exit
  --output OUTPUT       Output CSV file to write the results. If not provided, prints to stdout.
  --severity {very high,high,medium,low,very low}
                        filter data by threat for severity equal or above the selected value.

  --feature-classes FEATURE_CLASSES
                        filter data by feature class. Separate by `,`, if several.

$: tmxcaliber list threats path/to/threatmodels/ --output threats.csv

$: tmxcaliber list threats path/to/threatmodel.json
id,feature_class,name,description,access,hlgoal,mitre_attack,cvss,retired,cvss_severity,cvss_score
S3.T1,S3.FC5,Bucket takeover to gather data,"Bucket names are globally unique and can be recreated...","{""OPTIONAL"": ""s3:DeleteBucket""}",DataTheft,"TA0009,T1586",CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:L/A:N,false,Medium,5.2
S3.T2,S3.FC15,Unauthorized access to data or loss of control of SSE-C encrypted data via bucket replication,"Replication allows you to replicate objects and their metadata and change ownership....","{""AND"": [""s3:PutReplicationConfiguration"", ""iam:PassRole""]}",DataTheft,"TA0010,T1048",CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N,false,Medium,4.5
S3.T3,S3.FC1,Exfiltrate your data hosted on an external bucket by using compromised IAM credentials accessed over the Internet,IAM credentials can be compromised. An attacker can use...,"{""UNIQUE"": ""s3:GetObject""}",DataTheft,"TA0010,T1567",CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N,false,Medium,5.7
```

### List Controls
The `list controls` operation allows you to list all controls from a ThreatModel JSON file or a directory containing multiple JSON files. You can also specify an output file to write the results in CSV format.

```sh
$: tmxcaliber list controls -h
usage: tmxcaliber list controls [-h] [--output OUTPUT] source

positional arguments:
  source           Path to the ThreatModel JSON file or directory containing ThreatModel JSON files.

options:
  -h, --help       show this help message and exit
  --output OUTPUT  Output CSV file to write the results. If not provided, prints to stdout.

$: tmxcaliber list controls path/to/threatmodels/ --output controls.csv

$: tmxcaliber list controls path/to/threatmodel.json
objective,objective_description,id,coso,nist_csf,assured_by,depends_on,description,testing,effort,mitigate,feature_class,weighted_priority,weighted_priority_score,queryable_objective_id,queryable_id,retired
S3.CO1,Enforce encryption-in-transit,S3.C1,Preventative,Protect,S3.C2,S3.C119,"Block all unencrypted requests...",Make an unencrypte..,Low,"[{'threat': 'S3.T12', 'impact': 'Very High', 'priority': 4.0, 'max_dependency': None, 'priority_overall': 4.0, 'cvss': 'Medium'}]","['S3.FC1', 'S3.FC5']",High,3,1,1,false
S3.CO1,Enforce encryption-in-transit,S3.C2,Assurance,Detect,,,Verify the control blocking unencrypted requests and unauthorized TLS version(s) from IAM entities you control...,Remove the control blocking unencrypted requests and unauthorized ...,High,[],"['S3.FC1', 'S3.FC5']",High,3,1,2,false
S3.CO1,Enforce encryption-in-transit,S3.C3,Preventative,Protect,S3.C5,S3.C119,"Block all unencrypted requests...",Make an unencrypted AWS API call from one of your VPCs with VPC endpoint; it should be denied.,Low,"[{'threat': 'S3.T12', 'impact': 'Medium', 'priority': 2.0, 'max_dependency': None, 'priority_overall': 2.0, 'cvss': 'Medium'}]","['S3.FC1', 'S3.FC5']",Medium,2,1,3,false
```

## Contributing
If you'd like to contribute to the development of TMXcaliber, please submit a pull request or open an issue on the project's GitHub repository.
