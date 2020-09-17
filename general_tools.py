import logging
import random
import string


@staticmethod
def create_customized_logger(log_prefix, logger_level):
    def customized_logger(message):
        logger.info(f"[{log_prefix}]: {message}")

    logger = logging.getLogger("__name__")
    logger.setLevel(logger_level)
    return customized_logger


@staticmethod
def get_random_string(length, prefix=''):
    letters = string.ascii_lowercase
    result_str = prefix + ''.join(random.choice(letters) for i in range(length))
    return result_str
