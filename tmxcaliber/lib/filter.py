import re

IDS_INPUT_SEPARATOR = ","
PERMISSIONS_INPUT_SEPARATOR = ","
EVENTS_INPUT_SEPARATOR = ","
MITRE_TACTICS_INPUT_SEPARATOR = ","
IDS_FORMAT_REGEX = r"^\w+\.(fc|t|c|co)\d+$"
MITRE_TACTICS_FORMAT_REGEX = r"^ta\d{4}$"


class Filter:
    def __init__(
        self,
        severity: str = "",
        events: str = "",
        permissions: str = "",
        ids: str = "",
        mitre_tactics: str = "",
    ):
        self.severity = severity.lower() if severity else ""
        self.events = [
            x.lower().strip() for x in (events or "").split(EVENTS_INPUT_SEPARATOR) if x
        ]
        self.permissions = [
            x.lower().strip()
            for x in (permissions or "").split(PERMISSIONS_INPUT_SEPARATOR)
            if x
        ]
        self.ids = [
            x.lower().strip() for x in (ids or "").split(IDS_INPUT_SEPARATOR) if x
        ]
        self.mitre_tactics = [
            x.lower().strip()
            for x in (mitre_tactics or "").split(MITRE_TACTICS_INPUT_SEPARATOR)
            if x.strip()
        ]

        self.feature_classes: list[str] = []
        self.control_objectives: list[str] = []
        self.controls: list[str] = []
        self.threats: list[str] = []

        self.__validate()

    def __validate(self) -> None:
        for value in self.ids:
            match = re.match(IDS_FORMAT_REGEX, value)
            if match is None:
                raise ValueError(
                    f"Invalid ID format: {value}. Expected format is "
                    "'somestring.(FC|T|C|CO)somenumber'"
                )
            # Categorize the ID based on the regex groups
            if ".fc" in value:
                self.feature_classes.append(value)
            elif ".co" in value:
                self.control_objectives.append(value)
            elif ".c" in value:
                self.controls.append(value)
            elif ".t" in value:
                self.threats.append(value)
        for value in self.mitre_tactics:
            if re.match(MITRE_TACTICS_FORMAT_REGEX, value) is None:
                raise ValueError(
                    f"Invalid MITRE tactic format: {value}. Expected format is "
                    "'TA' and 4 digits, such as 'TA0010'"
                )
