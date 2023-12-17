import re

IDS_INPUT_SEPARATOR = ","
PERMISSIONS_INPUT_SEPARATOR = ','
FEATURE_CLASSES_INPUT_SEPARATOR = ','
EVENTS_INPUT_SEPARATOR = ','
IDS_FORMAT_REGEX = r"^\w+\.(fc|t|c|co)\d+$"

class Filter:
    def __init__(self, severity: str = "", events: list = [], permissions: list = [], feature_classes: list = [], ids: list = []):
        self.severity = severity.lower() if severity else ""
        self.events = [x.lower() for x in events or []]
        self.permissions = [x.lower() for x in permissions or []]
        self.feature_classes = [x.lower() for x in feature_classes or []]
        self.ids = [
            x.lower() for x in (ids and ids[0] or "")
                .split(IDS_INPUT_SEPARATOR) if x
        ]
        self.__validate()
    
    def __validate(self):
        id_prefix = None
        for value in self.ids:
            match = re.match(IDS_FORMAT_REGEX, value)
            if not match:
                ValueError(
                    f"invalid ID format: {value}. Expected format is "
                    "'somestring.(FC|T|C|CO)somenumber'"
                )
            current_prefix = match.group(1)
            if id_prefix is None:
                id_prefix = current_prefix
            elif id_prefix != current_prefix:
                ValueError(
                    "inconsistent ID types. Please provide IDs "
                    "with the same prefix (FC|T|C|CO)"
                )