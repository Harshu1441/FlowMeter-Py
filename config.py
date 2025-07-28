import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
OUTPUT_CSV = "output/live_flow_features.csv"
FLOW_TIMEOUT = 5  # seconds
SUBFLOW_WINDOW = 1  # seconds, configurable
BULK_INTERVAL = 0.1  # seconds, configurable
ACTIVE_THRESHOLD = 1  # seconds, configurable

# Ensure output directory exists
output_dir = os.path.dirname(OUTPUT_CSV)
if output_dir:
    os.makedirs(output_dir, exist_ok=True)
    logger.info(f"Output directory created or already exists: {output_dir}")