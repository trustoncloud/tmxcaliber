"""Tests for the CLI reader that lists feature classes from the raw document.

``get_feature_class_rows`` reads the JSON directly rather than through
:class:`~tmxcaliber.lib.threatmodel_data.ThreatModelData`, so it drops the
released dataset's ``{"retired": true}`` stubs itself.
"""

import json
from pathlib import Path

from tmxcaliber.cli import get_feature_class_rows


def test_feature_class_rows_skip_retired_stubs(tmp_path: Path) -> None:
    # Arrange
    source = tmp_path / "threatmodel.json"
    source.write_text(
        json.dumps(
            {
                "feature_classes": {
                    "S.FC1": {"name": "Live", "description": "d", "retired": False},
                    "S.FC2": {"retired": True},
                }
            }
        ),
        encoding="utf-8",
    )

    # Act
    rows = get_feature_class_rows(str(source))

    # Assert
    assert rows == [{"id": "S.FC1", "name": "Live", "description": "d"}]
