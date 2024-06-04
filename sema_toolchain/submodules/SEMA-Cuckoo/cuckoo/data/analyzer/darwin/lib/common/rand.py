import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import random
import string

def random_string(minimum, maximum=None):
    if maximum is None:
        maximum = minimum

    count = random.randint(minimum, maximum)
    return "".join(random.choice(string.ascii_letters) for x in range(count))

def random_integer(digits):
    start = 10 ** (digits - 1)
    end = (10 ** digits) - 1
    return random.randint(start, end)
