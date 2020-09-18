from logging import DEBUG

import pytest
from samr_client.ms_samr_client import samr_client
from general_tools import create_logger_with_prefix
from tests.conftest import LOCAL, GLOBAL

pytestmark = [pytest.mark.e2e_tests, pytest.mark.success]
logger = create_logger_with_prefix("E2E_TESTS", DEBUG)


@pytest.mark.parametrize("user_type", (LOCAL, GLOBAL))
def test__connect__add_user__get_users(user_type, credentials, random_computer_name_fixture):
    username_to_add = random_computer_name_fixture

    client = samr_client(credentials)
    logger.debug("Connecting to client...")
    client.connect()
    logger.debug("Connected!")

    logger.debug("Getting list of users:")
    users_list = client.get_users()
    logger.debug(f"Users list: {users_list}")

    logger.debug(f"Adding user {username_to_add}")
    client.add_user(username=username_to_add, user_type=user_type)
    logger.debug("User added!")

    logger.debug("Checking user list to see that the user was added successfully...")
    users_list_after_addition = client.get_users()
    added_users = set(users_list_after_addition).difference(set(users_list))
    logger.debug(f"Newly created users found are: {added_users}")

    logger.debug("Asserting success...")
    # note: other users might have been just added as well
    assert added_users, "No new user was created!"
    assert username_to_add in added_users, "The user was not created."
    # TODO - assert created user is of the correct type, else mention wrong type
