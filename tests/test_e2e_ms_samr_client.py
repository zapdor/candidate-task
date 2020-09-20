from logging import DEBUG

import pytest

from general_tools import create_logger_with_prefix
from ms_samr_client import MS_SAMR_Client
from tests.conftest import ENV_TARGET_INPUT

pytestmark = [pytest.mark.e2e_tests, pytest.mark.success]
logger = create_logger_with_prefix("E2E_TESTS", DEBUG)


@pytest.mark.usefixtures("mock_env_creds", "credentials_fixture", "random_computer_name_fixture")
@pytest.mark.parametrize("entry_type", MS_SAMR_Client.ENTRY_TYPES)
def test__e2e__connect__add_entry__get_entries(entry_type,
                                               mock_env_creds, credentials_fixture, random_computer_name_fixture):
    entry_name_to_add = random_computer_name_fixture

    client = MS_SAMR_Client(credentials_fixture[ENV_TARGET_INPUT])

    logger.debug(f"Adding {entry_type} {entry_name_to_add}")
    client.do_add_entry(args_str=f"{entry_type} {entry_name_to_add}")
    logger.debug("Entry added!")

    logger.debug("Getting list of entries:")
    entries_by_type = client.do_list_entries(f"{entry_type}")
    logger.debug(f"Entries list: {entries_by_type}")

    logger.debug("Asserting success...")

    assert entry_name_to_add in entries_by_type[entry_type], "The entry was not created."
