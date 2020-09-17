from os import getenv
import pytest

from general_tools import get_random_string

LOCAL = "local"
GLOBAL = "global"

ENV_DOMAIN_VAR = "candidate_domain"
ENV_USER_VAR = "candidate_username"
ENV_PASSWORD_VAR = "candidate_password"
ENV_TARGET_VAR = "candidate_target"
ENV_NEEDED_VARS = {ENV_DOMAIN_VAR, ENV_USER_VAR, ENV_PASSWORD_VAR, ENV_TARGET_VAR}


@pytest.fixture()
def credentials():
    existing_vars = {env_var.split('_')[1]: env_val for env_var in ENV_NEEDED_VARS if (env_val := getenv(env_var))}
    missing_env_vars = ENV_NEEDED_VARS.difference(existing_vars.keys())
    if missing_env_vars:
        raise EnvironmentError("Please add the missing vars to your environment and rerun tests: {}".
                               format(''.join(missing_env_vars)))

    return existing_vars


@pytest.fixture()
def random_computer_name(user_type):
    def _random_name():
        return get_random_string(length=10, prefix=f"TestUser_{user_type}")

    return _random_name()