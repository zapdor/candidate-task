import json
import os
from argparse import Namespace

import pytest

from AD_Objects import Target
from ms_samr_client import MS_SAMR_Client

ENV_DOMAIN_VAR = "domain"
ENV_USER_VAR = "username"
ENV_PASSWORD_VAR = "password"
ENV_TARGET_VAR = "target"
ENV_TARGET_INPUT = "input"

# Change these for different environment
DEFAULT_TEST_ENV_VARS = {
    ENV_DOMAIN_VAR: "CymptomTarget.local",
    ENV_USER_VAR: "Administrator",
    ENV_PASSWORD_VAR: "cymp",
    ENV_TARGET_VAR: "192.168.56.102",
}
DEFAULT_TEST_ENV = DEFAULT_TEST_ENV_VARS
DEFAULT_TEST_ENV[ENV_TARGET_INPUT] = "CymptomTarget.local/Administrator:cymp@192.168.56.102"

# Or replace this for different environment -
TEST_ENV = DEFAULT_TEST_ENV

# Tests Constants
DEFAULT_TARGET = DEFAULT_TEST_ENV[ENV_TARGET_INPUT]
PARSER_EXPECTED_OPTIONS = {
    ENV_TARGET_VAR: DEFAULT_TEST_ENV[ENV_TARGET_INPUT],
    "port": "445",
}

TARGET_DEFAULT_OPTIONS = {
    "target": DEFAULT_TARGET,
    "target_ip": DEFAULT_TEST_ENV_VARS[ENV_TARGET_VAR],
    "aesKey": None,
    "hashes": None,
    "k": False,
    "port": "445",
    "dc_ip": None,
}

EXPECTED_TARGET_ASDICT = {
    ENV_DOMAIN_VAR: "CymptomTarget.local",
    ENV_USER_VAR: "Administrator",
    ENV_PASSWORD_VAR: "cymp",
    "address": "192.168.56.102",
    'lmhash': '',
    'nthash': '',
    "options": None,
}


@pytest.fixture
def options_namespace():
    return _options_namespace()


@pytest.fixture
def target_asdict():
    return _target_asdict()


@pytest.fixture()
def target():
    kwargs = _target_asdict()
    target = Target(
        domain=kwargs["domain"],
        username=kwargs["username"],
        password=kwargs["password"],
        address=kwargs["address"],
        lmhash=kwargs["lmhash"],
        nthash=kwargs["nthash"],
        options=kwargs["options"]
    )

    return target


@pytest.fixture(scope="class")
def mock_env_creds(monkeysession):
    for cred_key, cred_val in TEST_ENV.items():
        monkeysession.setenv(cred_key, cred_val)


@pytest.fixture(scope="session")
def monkeysession():
    from _pytest.monkeypatch import MonkeyPatch
    mpatch = MonkeyPatch()
    yield mpatch
    mpatch.undo()


@pytest.fixture
def credentials_fixture():
    existing_vars = {env_var: env_val for env_var in TEST_ENV if (env_val := os.getenv(env_var))}
    missing_env_vars = set([env_var for env_var in TEST_ENV.keys()]).difference(existing_vars.keys())
    if missing_env_vars:
        raise EnvironmentError("Please add the missing vars to your environment and rerun tests: {}".
                               format(''.join(missing_env_vars)))

    return existing_vars


@pytest.fixture
def random_computer_name_fixture(entry_type):
    return MS_SAMR_Client.random_computer_name(entry_type)


def get_entries_list_from_stdout(capsys):
    output, err = capsys.readouterr()
    entries_by_type_str = output[output.index('{'):len(output) - output[::-1].index('}')]
    entries_by_type = json.loads(entries_by_type_str.replace("'", '"'))
    return entries_by_type


# region ---------- Helper Methods ----------

def _options_namespace():
    options_namespace = Namespace()
    for k, v in TARGET_DEFAULT_OPTIONS.items():
        setattr(options_namespace, k, v)

    return options_namespace


def _target_asdict():
    options_namespace = _options_namespace()
    target_asdict = EXPECTED_TARGET_ASDICT
    target_asdict["options"] = options_namespace

    return target_asdict

# endregion ---------- Helper Methods ----------
