"""The vendored contract keeps public and canonical field names distinct."""

from __future__ import annotations

from tmxcaliber.lib.remote import contract
from tmxcaliber.lib.remote.contract_naming import naming_violations


def test_vendored_contract_names_follow_the_wire_rule() -> None:
    """Every declared field and path or query parameter uses its native case."""
    assert naming_violations(contract.contract()) == []


def test_nested_fields_required_names_and_parameters_are_checked() -> None:
    """A bad field cannot hide inside a response schema or path template."""
    document = {
        "paths": {
            "/v1/models/{tm_id}": {
                "parameters": [
                    {"in": "path", "name": "tm_id"},
                    {"in": "query", "name": "feature_class"},
                    {"in": "header", "name": "X-Request-Id"},
                ],
                "schema": {
                    "properties": {
                        "tmId": {"type": "string"},
                        "nested": {
                            "properties": {"BadName": {"type": "string"}},
                            "required": ["BadName"],
                        },
                    },
                    "required": ["tm_id"],
                },
            }
        }
    }

    violations = naming_violations(document)

    assert len(violations) == 6
    assert any("'tm_id' must be camelCase" in violation for violation in violations)
    assert any(
        "'feature_class' must be camelCase" in violation for violation in violations
    )
    assert any("'BadName' must be camelCase" in violation for violation in violations)
    assert all("X-Request-Id" not in violation for violation in violations)


def test_canonical_source_names_are_snake_case_and_present() -> None:
    """Source metadata may use underscores but every canonical field needs it."""
    document = {
        "properties": {
            "featureClass": {
                "x-defined-by": "canonical-schema",
                "x-canonical-name": "feature_class",
            },
            "maxDependency": {
                "x-defined-by": "canonical-schema",
                "x-canonical-name": "maxDependency",
            },
            "priorityOverall": {"x-defined-by": "canonical-schema"},
        }
    }

    violations = naming_violations(document)

    assert len(violations) == 2
    assert any(
        "'maxDependency' must be snake_case" in violation for violation in violations
    )
    assert any("priorityOverall" in violation for violation in violations)
