import os
import sys
import logbook
from logbook import Logger,StreamHandler,FileHandler,TimedRotatingFileHandler
from logbook.more import ColorizedStderrHandler

def log_type(record,handler):
    log = "[{date}] [{level}] [{filename}] [{func_name}] [{lineno}] {msg}".format(
        date = record.time,                              # Log time
        level = record.level_name,                       # Log level
        filename = os.path.split(record.filename)[-1],   # file name
        func_name = record.func_name,                    # Function name
        lineno = record.lineno,                          # Line number
        msg = record.message                             # Log content
    )
    return log

# Log storage path
LOG_DIR = os.path.join("logs")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
# Log print to screen
log_std = ColorizedStderrHandler(bubble=True)
log_std.formatter = log_type
# Log print to file
log_file = TimedRotatingFileHandler(
    os.path.join(LOG_DIR, '%s.scdg.log' % 'log'),date_format='%Y-%m-%d', bubble=True, encoding='utf-8')
log_file.formatter = log_type

# Script log
run_log = Logger("script_log")
def init_logger():
    logbook.set_datetime_format("local")
    run_log.handlers = []
    run_log.handlers.append(log_file)
    run_log.handlers.append(log_std)