from .cache import get_cached_local_path_for
from .errors import FrameworkNotFoundError
from pandas import ExcelFile, read_excel

scf_versions = {
    "2023.4": {
        "url": "https://github.com/securecontrolsframework/securecontrolsframework/raw/d1428c74aa76a66d9e131e6a3e3d1e61af25bd3a/Secure%20Controls%20Framework%20(SCF)%20-%202023.4.xlsx",
        "sheet_name": "SCF 2023.4"
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
    local_scf = get_cached_local_path_for(scf_config['url'])
    # Read the Excel file
    xls = ExcelFile(local_scf)
    # Get the data from the worksheet
    scf_data = read_excel(xls, scf_config['sheet_name'])
    scf_data.columns = [col.replace('\n', ' ').strip() for col in scf_data.columns]
    if framework_name not in scf_data.columns:
        raise FrameworkNotFoundError(framework_name)
    # Keep only the columns "SCF #" and the one matching framework_name
    scf_data = scf_data[["SCF #", framework_name]]
    scf_data = scf_data.rename(columns={'SCF #': 'SCF'})
    scf_data = scf_data.assign(**{scf_data.columns[1]: scf_data.iloc[:, 1].str.split('\n')}).explode(scf_data.columns[1]).reset_index(drop=True)
    return scf_data
