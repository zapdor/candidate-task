import pytest

import os
from ms_samr_client import MS_SAMR_Client

ENV_DOMAIN_VAR = "domain"
ENV_USER_VAR = "username"
ENV_PASSWORD_VAR = "password"
ENV_TARGET_VAR = "target"
ENV_TARGET_INPUT = "input"

# Change these for different environment
DEFAULT_TEST_ENV_VARS = {
    ENV_DOMAIN_VAR: 'CymptomTarget.local',
    ENV_USER_VAR: 'Administrator',
    ENV_PASSWORD_VAR: 'cymp',
    ENV_TARGET_VAR: '192.168.56.102',
}
DEFAULT_TEST_ENV = DEFAULT_TEST_ENV_VARS
DEFAULT_TEST_ENV[ENV_TARGET_INPUT] = "CymptomTarget.local/Administrator:cymp@192.168.56.102"

# Or replace this for different environment -
TEST_ENV = DEFAULT_TEST_ENV


@pytest.fixture
def mock_env_creds(monkeypatch):
    for cred_key, cred_val in TEST_ENV.items():
        monkeypatch.setenv(cred_key, cred_val)


@pytest.fixture()
def credentials_fixture():
    existing_vars = {env_var: env_val for env_var in TEST_ENV if (env_val := os.getenv(env_var))}
    missing_env_vars = set([env_var for env_var in TEST_ENV.keys()]).difference(existing_vars.keys())
    if missing_env_vars:
        raise EnvironmentError("Please add the missing vars to your environment and rerun tests: {}".
                               format(''.join(missing_env_vars)))

    return existing_vars


@pytest.fixture()
def random_computer_name_fixture(entry_type):
    return MS_SAMR_Client.random_computer_name(entry_type)
