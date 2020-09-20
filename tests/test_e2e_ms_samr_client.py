from logging import DEBUG

import pytest

from general_tools import create_logger_with_prefix
from ms_samr_client import MS_SAMR_Client

pytestmark = [pytest.mark.e2e_tests, pytest.mark.success]
logger = create_logger_with_prefix("E2E_TESTS", DEBUG)


@pytest.mark.parametrize("entry_type", MS_SAMR_Client.ENTRY_TYPES)
@pytest.mark.usefixtures("_credentials", "_random_computer_name_fixture")
def test__e2e__connect__add_entry__get_entries(entry_type, _credentials, _random_computer_name_fixture):
    entry_name_to_add = _random_computer_name_fixture

    client = MS_SAMR_Client(_credentials)

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
