from logging import DEBUG

import pytest
from ms_samr_client import MS_SAMR_Client
from general_tools import create_logger_with_prefix

pytestmark = [pytest.mark.e2e_tests, pytest.mark.success]
logger = create_logger_with_prefix("E2E_TESTS", DEBUG)


@pytest.mark.parametrize("entry_type", MS_SAMR_Client.ENTRY_TYPES)
def test__connect__add_entry__get_entries(entry_type, credentials, random_computer_name_fixture):
    entry_name_to_add = random_computer_name_fixture

    client = MS_SAMR_Client(credentials)

    logger.debug(f"Adding {entry_type} {entry_name_to_add}")
    client.do_add_entry(entry_type=entry_type, entry_name=entry_name_to_add)
    logger.debug("Entry added!")

    assert client.connection_manager.connection.disconnect == False, "Connection did not close successfully!"

    logger.debug("Getting list of entries:")
    entries_list = client.do_list_entries(entry_type)
    logger.debug(f"Entries list: {entries_list}")

    logger.debug("Asserting success...")

    assert client.connection_manager.connection.disconnect == False, "Connection did not close successfully!"
    logger.debug("Connection closed successfully!")

    assert entry_name_to_add in entries_list, "The entry was not created."
