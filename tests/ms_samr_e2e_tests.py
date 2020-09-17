from logging import DEBUG

import pytest
from samr_client.samr_client import samr_client
from general_tools import create_customized_logger
from tests.conftest import LOCAL, GLOBAL

pytestmark = [pytest.mark.e2e_tests, pytest.mark.success]
logger = create_customized_logger("E2E_TESTS", DEBUG)

@pytest.mark.parametrize("user_type", (LOCAL, GLOBAL))
def test__connect__add_user__get_users(user_type, credentials, random_computer_name):
    username_to_add = random_computer_name

    client = samr_client(credentials)
    logger("Connecting to client...")
    client.connect()
    logger("Connected!")

    logger("Getting list of users:")
    users_list = client.get_users()
    logger(f"Users list: {users_list}")

    logger(f"Adding user {username_to_add}")
    client.add_user(username=username_to_add, user_type=user_type)
    logger("User added!")

    logger("Checking user list to see that the user was added successfully...")
    users_list_after_addition = client.get_users()
    added_users = set(users_list_after_addition).difference(set(users_list))
    logger(f"Newly created users found are: {added_users}")

    logger("Asserting success...")
    # note: other users might have been just added as well
    assert added_users, "No new user was created!"
    assert username_to_add in added_users, "The user was not created."
    # TODO - assert created user is of the correct type, else mention wrong type
