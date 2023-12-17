import re

IDS_INPUT_SEPARATOR = ","
PERMISSIONS_INPUT_SEPARATOR = ','
FEATURE_CLASSES_INPUT_SEPARATOR = ','
EVENTS_INPUT_SEPARATOR = ','
IDS_FORMAT_REGEX = r"^\w+\.(FC|T|C|CO)\d+$"
FEATURE_CLASSES_FORMAT_REGEX = r"^\w+\.FC\d+$"

class Filter:
    def __init__(self, severity: str = "", events: str = "", permissions: str = "", feature_classes: str = "", ids: str = ""):
        self.severity = severity.lower() if severity else ""
        self.events = [x.lower().strip() for x in (events or '').split(EVENTS_INPUT_SEPARATOR) if x]
        self.permissions = [x.lower().strip() for x in (permissions or '').split(PERMISSIONS_INPUT_SEPARATOR) if x]
        self.feature_classes = [x.upper().strip() for x in (feature_classes or '').split(FEATURE_CLASSES_INPUT_SEPARATOR) if x]
        self.ids = [x.upper().strip() for x in (ids or '').split(IDS_INPUT_SEPARATOR) if x]
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
        for value in self.feature_classes:
            match = re.match(IDS_FORMAT_REGEX, value)
            if not match:
                ValueError(
                    f"invalid ID format: {value}. Expected format is "
                    "'somestring.(FC|T|C|CO)somenumber'"
                )
