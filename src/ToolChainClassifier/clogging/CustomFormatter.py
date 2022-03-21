import logging


class CustomFormatter(logging.Formatter):

    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = [
        "\033[1;30;40m",
        "\033[1;31;40m",
        "\033[1;32;40m",
        "\033[1;33;40m",
        "\033[1;34;40m",
        "\033[1;35;40m",
        "\033[1;36;40m",
        "\033[1;37;40m",
    ]

    # The background is set with 40 plus the number of the color, and the foreground with 30

    # These are the sequences need to get colored ouput
    RESET_SEQ = "\033[0m"
    COLOR_SEQ = "\033[1;%dm"
    BOLD_SEQ = "\033[1m"

    format = "%(levelname)s - %(asctime)s - %(name)s - %(message)s"  #  (%(filename)s:%(lineno)d)

    FORMATS = {
        logging.DEBUG: str(BLUE) + format + RESET_SEQ,
        logging.INFO: str(GREEN) + format + RESET_SEQ,
        logging.WARNING: str(YELLOW) + format + RESET_SEQ,
        logging.ERROR: str(RED) + format + RESET_SEQ,
        logging.CRITICAL: BOLD_SEQ + format + RESET_SEQ,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
