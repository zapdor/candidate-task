import logging
import os
import random
import string


def create_logger_with_prefix(log_prefix=__name__, logger_level=logging.INFO):
    if os.getenv("SAMR_DEBUG") == "1":
        logger_level = logging.DEBUG

    log_format = f"[{log_prefix}]: %(message)s"
    logger = logging.getLogger()
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
