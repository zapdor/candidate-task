from logging import DEBUG

import pytest
from ms_samr_client import MS_SAMR_Client
from general_tools import create_logger_with_prefix

pytestmark = [pytest.mark.e2e_tests, pytest.mark.success]
logger = create_logger_with_prefix("E2E_TESTS", DEBUG)


@pytest.mark.parametrize("entry_type", MS_SAMR_Client.USER_TYPES)
def test__connect__add_entry__get_entries(entry_type, credentials, random_computer_name_fixture):
    entry_name_to_add = random_computer_name_fixture

    client = MS_SAMR_Client(credentials)

    added_entries = None

    logger.debug("Connecting to client...")
    with client.connection_manager(client.target) as dce_connection:
        logger.debug("Connection succeeded!")

        logger.debug("Getting list of entries:")
        entries_list = client.get_entries()
        logger.debug(f"Entries list: {entries_list}")

        logger.debug(f"Adding {entry_type} {entry_name_to_add}")
        client.add_entry(entry_name=entry_name_to_add, entry_type=entry_type)
        logger.debug("User added!")

        logger.debug("Checking user list to see that the user was added successfully...")
        entries_list_after_addition = client.get_entries()
        added_entries = set(entries_list_after_addition).difference(set(entries_list))
        logger.debug(f"Newly created entries found are: {added_entries}")

        logger.debug("Asserting success...")

    assert client.connection_manager.connection.disconnect == False, "Connection did not close successfully!"
    logger.debug("Connection closed successfully!")

    # note: other entries might have been just added as well
    assert added_entries, "No new entry was created!"
    assert entry_name_to_add in added_entries, "The entry was not created."
    # TODO - assert created user is of the correct type, else mention wrong type
