import logging
import random
import string


@staticmethod
def create_logger_with_prefix(log_prefix=__name__, logger_level=logging.INFO):
    log_format = f"[{log_prefix}]: %(message)s"
    logging.basicConfig(format=log_format, level=logger_level)
    logger = logging.getLogger("__name__")
    return logger


@staticmethod
def get_random_string(length, prefix=''):
    letters = string.ascii_lowercase
    result_str = prefix + ''.join(random.choice(letters) for i in range(length))
    return result_str


@staticmethod
def random_computer_name(user_type):
    return get_random_string(length=10, prefix=f"TestUser_{user_type}")
