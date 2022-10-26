import pytest

from cleanerapi.helpers.settings import config_validators, default_config


def test_same_coverage() -> None:
    assert set(default_config.keys()) == set(config_validators.keys())


@pytest.mark.parametrize("field", default_config.keys())
def test_field(field: str) -> None:
    assert config_validators[field](default_config[field])
