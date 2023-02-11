from server import app
from server import ConfigFileNotFound
from server import setup_logging
import logging
import sys

if __name__ == "__main__":
    setup_logging()
    try:
        app.run()
    except ConfigFileNotFound as e:
        logging.critical(e)
        sys.exit(1)