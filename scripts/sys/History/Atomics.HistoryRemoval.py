
import os
import shutil
import time
import logging
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AluminumHistoryRemover:
    def __init__(self):
        self.browser_name = "Aluminum"
        self.history_locations: Dict[str, Path] = {
            "windows": Path(os.environ.get("LOCALAPPDATA", "")) / "Aluminum" / "User Data" / "Default" / "History",
            "macos": Path.home() / "Library" / "Application Support" / "Aluminum" / "Default" / "History",
            "linux": Path.home() / ".config" / "aluminum" / "Default" / "History"
        }
        self.backup_dir = Path.home() / f"{self.browser_name}_History_Backup_{int(time.time())}"

    def determine_os(self) -> str:
        """Determine the operating system."""
        if os.name == "nt":
            return "windows"
        elif os.name == "posix":
            if os.uname().sysname.lower() == "darwin":
                return "macos"
            else:
                return "linux"
        else:
            raise OSError("Unsupported operating system")

    def create_backup(self, history_path: Path) -> None:
        """Create a backup of the history file."""
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            shutil.copy2(history_path, self.backup_dir)
            logger.info(f"Backup created at: {self.backup_dir}")
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise

    def remove_history_file(self, history_path: Path) -> None:
        """Securely remove the history file."""
        try:
            if history_path.exists():
                # Overwrite the file with random data before deletion
                with open(history_path, "wb") as f:
                    f.write(os.urandom(history_path.stat().st_size))
                os.remove(history_path)
                logger.info(f"History file removed: {history_path}")
            else:
                logger.warning(f"History file not found: {history_path}")
        except Exception as e:
            logger.error(f"Failed to remove history file: {e}")
            raise

    def clear_related_files(self, base_path: Path) -> None:
        """Clear related history files and directories."""
        related_paths = [
            base_path.parent / "History-journal",
            base_path.parent / "Visited Links",
            base_path.parent / "Top Sites",
            base_path.parent / "Shortcuts",
            base_path.parent / "Login Data",
            base_path.parent / "Web Data"
        ]

        for path in related_paths:
            try:
                if path.is_file():
                    self.remove_history_file(path)
                elif path.is_dir():
                    shutil.rmtree(path)
                    logger.info(f"Removed directory: {path}")
            except Exception as e:
                logger.error(f"Failed to clear related file/directory {path}: {e}")

    def vacuum_database(self, db_path: Path) -> None:
        """Vacuum the SQLite database to reclaim space and optimize performance."""
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.execute("VACUUM")
            conn.close()
            logger.info(f"Vacuumed database: {db_path}")
        except Exception as e:
            logger.error(f"Failed to vacuum database {db_path}: {e}")

    def clear_cache(self, cache_dir: Path) -> None:
        """Clear the browser cache."""
        try:
            if cache_dir.exists():
                shutil.rmtree(cache_dir)
                os.makedirs(cache_dir)
                logger.info(f"Cleared cache directory: {cache_dir}")
            else:
                logger.warning(f"Cache directory not found: {cache_dir}")
        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")

    def remove_history_atomic(self) -> None:
        """Remove browser history atomically."""
        os_type = self.determine_os()
        history_path = self.history_locations.get(os_type)

        if not history_path:
            raise ValueError(f"Unsupported operating system: {os_type}")

        try:
            # Step 1: Create a backup
            self.create_backup(history_path)

            # Step 2: Remove the main history file
            self.remove_history_file(history_path)

            # Step 3: Clear related files and directories
            self.clear_related_files(history_path)

            # Step 4: Vacuum the database
            self.vacuum_database(history_path.parent / "Web Data")

            # Step 5: Clear the cache
            cache_dir = history_path.parent.parent / "Cache"
            self.clear_cache(cache_dir)

            logger.info("History removal completed successfully")
        except Exception as e:
            logger.error(f"History removal failed: {e}")
            self.restore_backup(history_path)

    def restore_backup(self, history_path: Path) -> None:
        """Restore the backup if the removal process fails."""
        try:
            backup_file = self.backup_dir / history_path.name
            if backup_file.exists():
                shutil.copy2(backup_file, history_path)
                logger.info(f"Backup restored from: {backup_file}")
            else:
                logger.warning("Backup file not found, unable to restore")
        except Exception as e:
            logger.error(f"Failed to restore backup: {e}")

    def run(self) -> None:
        """Execute the history removal process with proper error handling and logging."""
        logger.info(f"Starting {self.browser_name} history removal process")
        try:
            self.remove_history_atomic()
        except Exception as e:
            logger.critical(f"Critical error during history removal: {e}")
        finally:
            logger.info(f"{self.browser_name} history removal process completed")

if __name__ == "__main__":
    remover = AluminumHistoryRemover()
    remover.run()
