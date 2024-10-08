import logging
import os
import time
from termcolor import colored

# Custom logging levels similar to sqlmap
PAYLOAD = 25  # Between INFO and WARNING
TRAFFIC_OUT = 15
TRAFFIC_IN = 16

logging.addLevelName(PAYLOAD, "PAYLOAD")
logging.addLevelName(TRAFFIC_OUT, "TRAFFIC OUT")
logging.addLevelName(TRAFFIC_IN, "TRAFFIC IN")

# Create log directory if it doesn't exist
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Define colors for different log levels
log_colors = {
    'DEBUG': 'blue',
    'INFO': 'green',
    'PAYLOAD': 'cyan',
    'TRAFFIC OUT': 'yellow',
    'TRAFFIC IN': 'yellow',
    'WARNING': 'yellow',
    'ERROR': 'red',
    'CRITICAL': 'red',
}

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        levelname = record.levelname
        message = super().format(record)
        color = log_colors.get(levelname, 'white')
        return colored(message, color)

# Define log format for console with colors and timestamps
console_log_format = "%(asctime)s [%(levelname)s] %(message)s"
console_formatter = ColoredFormatter(
    fmt=console_log_format,
    datefmt='[%H:%M:%S]'  # Time format for console logs
)

# Define log format for file without colors
file_log_format = "%(asctime)s - [%(levelname)s] %(name)s %(message)s"
file_formatter = logging.Formatter(file_log_format)

# Create logger
logger = logging.getLogger('xss911')
logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all log levels

# Create handlers
console_handler = logging.StreamHandler()
console_handler.setFormatter(console_formatter)
console_handler.setLevel(logging.DEBUG)  # Ensure console handler is set to DEBUG level

log_filename = time.strftime("logs/xss911_%Y%m%d_%H%M%S.log", time.localtime())
file_handler = logging.FileHandler(log_filename, encoding="utf-8")
file_handler.setFormatter(file_formatter)

# Add handlers to logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# Custom log level functions for easier logging
def log_payload(message):
    """
    Log messages for payloads during XSS testing.
    """
    logger.log(PAYLOAD, message)

def log_traffic_out(message):
    """
    Log messages for outgoing requests.
    """
    logger.log(TRAFFIC_OUT, message)

def log_traffic_in(message):
    """
    Log messages for incoming responses.
    """
    logger.log(TRAFFIC_IN, message)

def set_verbose_mode(is_verbose):
    """
    Set the verbosity of the logger.
    """
    if is_verbose:
        console_handler.setLevel(logging.DEBUG)
        logger.info("VERBOSE MODE: Showing all logs")
    else:
        console_handler.setLevel(logging.WARNING)
        logger.warning("SILENT MODE: Only showing warnings and errors")
        logger.warning(f'Visit this log file to see all logs: {log_filename}')

