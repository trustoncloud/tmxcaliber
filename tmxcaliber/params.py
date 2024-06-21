import os

GUARDDUTY_PATTERN_NAME = "guardduty_findings"
CURR_DIR = os.getcwd()
XML_DIR = os.path.join(CURR_DIR, "xmls")
IMG_DIR = os.path.join(CURR_DIR, "img")

GUARDDUTY_FINDINGS = (
    r"("
    + "|".join(
        [
            "Trojan",
            "UnauthorizedAccess",
            "Discovery",
            "Exfiltration",
            "Impact",
            "PenTest",
            "Policy",
            "Stealth",
            "CredentialAccess",
            "Execution",
            "CryptoCurrency",
            "Backdoor",
            "PrivilegeEscalation",
            "DefenseEvasion",
            "InitialAccess",
            "Persistence",
            "Recon",
        ]
    )
    + r")"
    + r":\w+\/[\w!.-]+"
)

METADATA_MISSING = "Not available in framework-metadata file"
MISSING_OUTPUT_ERROR = (
    "The '--output-removed' flag requires '--output' to be specified."
)


class Operation:
    filter = "filter"
    map = "map"
    scan = "scan"
    generate = "generate"
    list = "list"
    add_mapping = "add-mapping"
    create_change_log = "create-change-log"


class ListOperation:
    threats = "threats"
    controls = "controls"
