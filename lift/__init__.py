import logging

logger = logging.getLogger(__name__)

import ipdb; ipdb.set_trace()
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(module)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
