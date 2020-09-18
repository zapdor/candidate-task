from logging import DEBUG

import pytest
from samr_client.ms_samr_client import samr_client
from general_tools import create_logger_with_prefix
from tests.conftest import LOCAL, GROUP

pytestmark = [pytest.mark.e2e_tests, pytest.mark.success]
logger = create_logger_with_prefix("E2E_TESTS", DEBUG)


@pytest.mark.parametrize("entry_type", (LOCAL, GROUP))
def test__connect__add_entry__get_entries(entry_type, credentials, random_computer_name_fixture):
    entry_name_to_add = random_computer_name_fixture

    client = samr_client(credentials)
    logger.debug("Connecting to client...")
    client.connect()
    logger.debug("Connected!")

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
    # note: other entries might have been just added as well
    assert added_entries, "No new entry was created!"
    assert entry_name_to_add in added_entries, "The entry was not created."
    # TODO - assert created user is of the correct type, else mention wrong type
