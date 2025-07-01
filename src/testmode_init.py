import time
import uuid
import logging
import sys
# Setup debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='DEBUG: %(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

logger.debug("Initializing testmode_init module")

import helper_inbox
import helper_sql
logger.debug("Imported helper modules: helper_inbox, helper_sql")

# Test data samples
logger.debug("Defining test data samples")
sample_deterministic_addr4 = 'BM-2cWzSnwjJ7yRP3nLEWUV5LisTZyREWSzUK'
sample_inbox_msg_ids = [
    '27e644765a3e4b2e973ee7ccf958ea20',
    '51fc5531-3989-4d69-bbb5-68d64b756f5b',
    '2c975c515f8b414db5eea60ba57ba455',
    'bc1f2d8a-681c-4cc0-9a12-6067c7e1ac24'
]
logger.debug("Sample address: %s", sample_deterministic_addr4)
logger.debug("Sample message IDs: %s", sample_inbox_msg_ids)

def populate_api_test_data():
    '''Adding test records in inbox table'''
    logger.debug("populate_api_test_data() called")
    
    logger.debug("Waiting for SQL to be ready...")
    helper_sql.sql_ready.wait()
    logger.debug("SQL is now ready")

    # Prepare test data
    logger.debug("Preparing test data records")
    
    test_data = [
        (
            sample_inbox_msg_ids[0], sample_deterministic_addr4,
            sample_deterministic_addr4, 'Test1 subject', int(time.time()),
            'Test1 body', 'inbox', 2, 0, uuid.uuid4().bytes
        ),
        (
            sample_inbox_msg_ids[1], sample_deterministic_addr4,
            sample_deterministic_addr4, 'Test2 subject', int(time.time()),
            'Test2 body', 'inbox', 2, 0, uuid.uuid4().bytes
        ),
        (
            sample_inbox_msg_ids[2], sample_deterministic_addr4,
            sample_deterministic_addr4, 'Test3 subject', int(time.time()),
            'Test3 body', 'inbox', 2, 0, uuid.uuid4().bytes
        ),
        (
            sample_inbox_msg_ids[3], sample_deterministic_addr4,
            sample_deterministic_addr4, 'Test4 subject', int(time.time()),
            'Test4 body', 'inbox', 2, 0, uuid.uuid4().bytes
        )
    ]
    
    logger.debug("Prepared %d test records", len(test_data))
    
    # Insert test data
    for i, record in enumerate(test_data, 1):
        logger.debug("Inserting test record %d: ID=%s, Subject='%s'", 
                   i, record[0], record[3])
        try:
            helper_inbox.insert(record)
            logger.debug("Successfully inserted record %d", i)
        except Exception as e:
            logger.error("Failed to insert record %d: %s", i, str(e))
            raise

    logger.debug("Finished inserting all test records")

logger.debug("testmode_init module initialization complete")
