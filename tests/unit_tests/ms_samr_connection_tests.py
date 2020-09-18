from logging import DEBUG

import pytest

from general_tools import create_logger_with_prefix

pytestmark = [pytest.mark.e2e_tests, pytest.mark.success]
logger = create_logger_with_prefix("CONNECTION_MANAGER_UNIT_TESTS", DEBUG)
