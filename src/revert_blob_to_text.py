import sys
import logging
import helper_startup
import state
import shutil
import sqlite3

# Setup debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='DEBUG: %(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

expected_ver = 11
logger.debug("Script initialized with expected database version: %d", expected_ver)

def main():
    try:
        logger.debug("Looking up database file")
        helper_startup.loadConfig()
        db_path = state.appdata + "messages.dat"
        logger.debug("Database path: %s", db_path)
        
        db_backup_path = db_path + ".blob-keys"
        logger.debug("Backup path: %s", db_backup_path)
        
        logger.debug("Creating database backup")
        shutil.copyfile(db_path, db_backup_path)
        logger.info("Successfully created backup at %s", db_backup_path)

        logger.debug("Opening database connection")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        logger.debug("Database connection established")

        logger.debug("Checking database version")
        cur.execute("SELECT value FROM settings WHERE key='version';")
        version_result = cur.fetchall()
        ver = int(version_result[0][0])
        logger.debug("Current database version: %d", ver)
        
        if ver != expected_ver:
            logger.error("Database version mismatch. Expected %d, found %d", expected_ver, ver)
            conn.close()
            logger.error("Exiting due to version mismatch")
            sys.exit(1)
        
        logger.info("Database version check passed")

        logger.debug("Beginning database conversion")
        
        # Convert inbox table
        q = "UPDATE inbox SET msgid=CAST(msgid AS TEXT), sighash=CAST(sighash AS TEXT);"
        logger.debug("Executing: %s", q)
        cur.execute(q)
        logger.debug("Inbox table conversion complete")
        
        # Convert pubkeys table
        q = "UPDATE pubkeys SET transmitdata=CAST(transmitdata AS TEXT);"
        logger.debug("Executing: %s", q)
        cur.execute(q)
        logger.debug("Pubkeys table conversion complete")
        
        # Convert sent table
        q = "UPDATE sent SET msgid=CAST(msgid AS TEXT), toripe=CAST(toripe AS TEXT), ackdata=CAST(ackdata AS TEXT);"
        logger.debug("Executing: %s", q)
        cur.execute(q)
        logger.debug("Sent table conversion complete")

        logger.debug("Committing changes to database")
        conn.commit()
        logger.info("Database conversion completed successfully")

    except Exception as e:
        logger.error("Error during conversion: %s", str(e))
        logger.debug("Stack trace:\n%s", traceback.format_exc())
        if 'conn' in locals():
            conn.rollback()
            logger.debug("Rolled back any pending changes")
        raise
    finally:
        if 'conn' in locals():
            logger.debug("Closing database connection")
            conn.close()
            logger.debug("Database connection closed")
    
    logger.info("Script execution finished successfully")

if __name__ == "__main__":
    logger.debug("Starting script execution")
    main()
