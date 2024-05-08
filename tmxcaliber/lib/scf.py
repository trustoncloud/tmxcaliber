from .cache import get_cached_local_path_for
from .errors import FrameworkNotFoundError
from pandas import ExcelFile, read_excel

scf_versions = {
    "2023.4": {
        "url": "https://github.com/securecontrolsframework/securecontrolsframework/raw/d1428c74aa76a66d9e131e6a3e3d1e61af25bd3a/Secure%20Controls%20Framework%20(SCF)%20-%202023.4.xlsx",
        "sheet_name": "SCF 2023.4",
    },
    "2024.1.1": {
        "url": "https://github.com/securecontrolsframework/securecontrolsframework/raw/b14c2058fca9bb0085980cbb077b0bd3a71a09ea/Secure%20Controls%20Framework%20(SCF)%20-%202024.1.1.xlsx",
        "sheet_name": "SCF 2024.1.1",
    },
    # Add more versions as needed
}


def get_supported_scf():
    return scf_versions.keys()


def get_scf_config(version):
    if version in scf_versions:
        return scf_versions[version]
    else:
        raise ValueError("Unsupported SCF version requested")


def get_scf_data(version, framework_name):
    scf_config = get_scf_config(version)
    local_scf = get_cached_local_path_for(scf_config["url"])
    # Read the Excel file
    xls = ExcelFile(local_scf, engine="openpyxl")
    # Get the data from the worksheet
    scf_data = read_excel(xls, scf_config["sheet_name"])
    scf_data.columns = [col.replace("\n", " ").strip() for col in scf_data.columns]
    if framework_name not in scf_data.columns:
        raise FrameworkNotFoundError(framework_name)
    # Keep only the columns "SCF #" and the one matching framework_name
    scf_data = scf_data[["SCF #", framework_name]]
    scf_data = scf_data.rename(columns={"SCF #": "SCF"})
    scf_data = (
        scf_data.assign(**{scf_data.columns[1]: scf_data.iloc[:, 1].str.split("\n")})
        .explode(scf_data.columns[1])
        .reset_index(drop=True)
    )
    scf_data = scf_data.applymap(lambda x: x.strip() if isinstance(x, str) else x)
    return scf_data
