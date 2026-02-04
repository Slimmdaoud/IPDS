import logging
from logging.handlers import RotatingFileHandler

LOG_FILE = "ids.log"

logger = logging.getLogger("IDS")
logger.setLevel(logging.INFO)

# Handler qui écrit dans ids.log, rotation 1 Mo, 3 fichiers max
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3)
formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s"
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def log_alert(alert_type, src_ip, dst_ip, details):
    """
    Écrit une alerte dans ids.log.
    """
    msg = f"{alert_type} src={src_ip} dst={dst_ip} details={details}"
    logger.warning(msg)
