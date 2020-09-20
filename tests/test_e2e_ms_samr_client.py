from logging import DEBUG

import pytest

from general_tools import create_logger_with_prefix
from ms_samr_client import MS_SAMR_Client
from tests.conftest import ENV_TARGET_INPUT, get_entries_list_from_stdout

pytestmark = [pytest.mark.e2e_tests, pytest.mark.success]
logger = create_logger_with_prefix("SAMR_E2E_TESTS", DEBUG)


@pytest.mark.parametrize("entry_type", MS_SAMR_Client.ENTRY_TYPES)
def test__e2e__connect__add_entry__get_entries(entry_type,
                                               mock_env_creds, credentials_fixture, random_computer_name_fixture,
                                               capsys):
    entry_name_to_add = random_computer_name_fixture

    client = MS_SAMR_Client(credentials_fixture[ENV_TARGET_INPUT])

    logger.debug(f"Adding {entry_type} {entry_name_to_add}")
    client.do_add_entry(args_str=f"{entry_type} {entry_name_to_add}")
    logger.debug("Entry added!")

    logger.debug("Getting list of entries:")
    client.do_list_entries(f"{entry_type}")
    entries_by_type = get_entries_list_from_stdout(capsys)
    logger.debug(f"Entries list: {entries_by_type}")

    assert entry_name_to_add in entries_by_type[entry_type], "The entry was not created."
    logger.debug("Success!")
