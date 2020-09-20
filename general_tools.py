import logging
import os
import random
import string


def create_logger_with_prefix(log_prefix, logger_level=logging.INFO):
    """
    Creates a log with given prefix for any desired class.
    format for the messages is: '[log_prefix]: log_message'
    :param log_prefix:
    :param logger_level:
    :return: prefix logger
    """
    if os.getenv("SAMR_DEBUG") == "1":
        logger_level = logging.DEBUG

    log_format = f"[{log_prefix}]: %(message)s"
    logger = logging.getLogger(log_prefix)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(log_format)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    logger.setLevel(logger_level)

    return logger


def get_random_string(length, prefix=''):
    letters = string.ascii_lowercase
    result_str = prefix + ''.join(random.choice(letters) for i in range(length))
    return result_str
