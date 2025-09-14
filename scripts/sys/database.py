
import sqlite3
import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AluminumDatabase:
    """
    A class to handle all database operations for the Aluminum web browser.
    This includes managing connections, executing queries, and handling various
    browser-related data such as history, bookmarks, and settings.
    """

    def __init__(self, db_path: str = "aluminum_data.db"):
        """
        Initialize the database connection.

        :param db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.conn = None
        self.create_tables()

    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        Ensures that connections are properly closed after use.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            yield conn
        finally:
            if conn:
                conn.close()

    def create_tables(self):
        """
        Create necessary tables if they don't exist.
        This includes tables for history, bookmarks, settings, and cache.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Create history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    title TEXT,
                    visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    visit_count INTEGER DEFAULT 1
                )
            ''')

            # Create bookmarks table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bookmarks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    title TEXT,
                    added_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    folder TEXT DEFAULT 'root'
                )
            ''')

            # Create settings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')

            # Create cache table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cache (
                    url TEXT PRIMARY KEY,
                    content BLOB,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.commit()
        logger.info("Database tables created successfully")

    def add_history_entry(self, url: str, title: str):
        """
        Add a new entry to the browsing history or update if exists.

        :param url: The URL of the visited page
        :param title: The title of the visited page
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO history (url, title)
                VALUES (?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    visit_count = visit_count + 1,
                    visit_time = CURRENT_TIMESTAMP
            ''', (url, title))
            conn.commit()
        logger.debug(f"Added history entry: {url}")

    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve browsing history.

        :param limit: Maximum number of entries to retrieve
        :return: List of dictionaries containing history entries
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM history
                ORDER BY visit_time DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def add_bookmark(self, url: str, title: str, folder: str = 'root'):
        """
        Add a new bookmark.

        :param url: The URL of the bookmarked page
        :param title: The title of the bookmarked page
        :param folder: The folder to organize the bookmark (default is 'root')
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO bookmarks (url, title, folder)
                VALUES (?, ?, ?)
            ''', (url, title, folder))
            conn.commit()
        logger.info(f"Added bookmark: {title} - {url}")

    def get_bookmarks(self, folder: str = None) -> List[Dict[str, Any]]:
        """
        Retrieve bookmarks, optionally filtered by folder.

        :param folder: The folder to filter bookmarks (optional)
        :return: List of dictionaries containing bookmark entries
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if folder:
                cursor.execute('SELECT * FROM bookmarks WHERE folder = ?', (folder,))
            else:
                cursor.execute('SELECT * FROM bookmarks')
            return [dict(row) for row in cursor.fetchall()]

    def update_setting(self, key: str, value: str):
        """
        Update a browser setting.

        :param key: The setting key
        :param value: The setting value
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO settings (key, value)
                VALUES (?, ?)
            ''', (key, value))
            conn.commit()
        logger.info(f"Updated setting: {key}")

    def get_setting(self, key: str) -> Optional[str]:
        """
        Retrieve a browser setting.

        :param key: The setting key
        :return: The setting value if found, None otherwise
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
            result = cursor.fetchone()
            return result['value'] if result else None

    def add_to_cache(self, url: str, content: bytes):
        """
        Add or update a cache entry.

        :param url: The URL of the cached content
        :param content: The cached content as bytes
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO cache (url, content, last_updated)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (url, content))
            conn.commit()
        logger.debug(f"Added to cache: {url}")

    def get_from_cache(self, url: str) -> Optional[bytes]:
        """
        Retrieve cached content for a given URL.

        :param url: The URL to retrieve from cache
        :return: Cached content as bytes if found, None otherwise
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT content FROM cache WHERE url = ?', (url,))
            result = cursor.fetchone()
            return result['content'] if result else None

    def clear_cache(self):
        """
        Clear all cached content.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM cache')
            conn.commit()
        logger.info("Cache cleared")

    def optimize_database(self):
        """
        Optimize the database by running VACUUM command.
        This should be run periodically to keep the database performant.
        """
        with self.get_connection() as conn:
            conn.execute('VACUUM')
        logger.info("Database optimized")

    def backup_database(self, backup_path: str):
        """
        Create a backup of the database.

        :param backup_path: Path where the backup will be stored
        """
        with self.get_connection() as conn:
            backup_conn = sqlite3.connect(backup_path)
            conn.backup(backup_conn)
            backup_conn.close()
        logger.info(f"Database backed up to: {backup_path}")

    def restore_database(self, backup_path: str):
        """
        Restore the database from a backup.

        :param backup_path: Path to the backup file
        """
        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup file not found: {backup_path}")

        with self.get_connection() as conn:
            backup_conn = sqlite3.connect(backup_path)
            backup_conn.backup(conn)
            backup_conn.close()
        logger.info(f"Database restored from: {backup_path}")

    def get_most_visited_sites(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get the most frequently visited sites.

        :param limit: Maximum number of sites to retrieve
        :return: List of dictionaries containing site information
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT url, title, visit_count
                FROM history
                ORDER BY visit_count DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def search_history(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Search the browsing history for a given query.

        :param query: Search query
        :param limit: Maximum number of results to retrieve
        :return: List of dictionaries containing matching history entries
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM history
                WHERE url LIKE ? OR title LIKE ?
                ORDER BY visit_time DESC
                LIMIT ?
            ''', (f'%{query}%', f'%{query}%', limit))
            return [dict(row) for row in cursor.fetchall()]

    def delete_history_entry(self, url: str):
        """
        Delete a specific entry from the browsing history.

        :param url: The URL of the entry to delete
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM history WHERE url = ?', (url,))
            conn.commit()
        logger.info(f"Deleted history entry: {url}")

    def clear_history(self, days: int = None):
        """
        Clear browsing history, optionally specifying a time range.

        :param days: Number of days to keep (None means clear all)
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if days is None:
                cursor.execute('DELETE FROM history')
            else:
                cursor.execute('''
                    DELETE FROM history
                    WHERE visit_time < datetime('now', ?)
                ''', (f'-{days} days',))
            conn.commit()
        logger.info(f"Cleared history {'completely' if days is None else f'older than {days} days'}")

    def get_database_size(self) -> int:
        """
        Get the current size of the database file in bytes.

        :return: Size of the database file in bytes
        """
        return os.path.getsize(self.db_path)

    def export_bookmarks(self, export_path: str):
        """
        Export bookmarks to a JSON file.

        :param export_path: Path where the JSON file will be saved
        """
        import json
        bookmarks = self.get_bookmarks()
        with open(export_path, 'w') as f:
            json.dump(bookmarks, f, indent=2)
        logger.info(f"Bookmarks exported to: {export_path}")

    def import_bookmarks(self, import_path: str):
        """
        Import bookmarks from a JSON file.

        :param import_path: Path to the JSON file containing bookmarks
        """
        import json
        with open(import_path, 'r') as f:
            bookmarks = json.load(f)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for bookmark in bookmarks:
                cursor.execute('''
                    INSERT OR REPLACE INTO bookmarks (url, title, folder)
                    VALUES (?, ?, ?)
                ''', (bookmark['url'], bookmark['title'], bookmark.get('folder', 'root')))
            conn.commit()
        logger.info(f"Bookmarks imported from: {import_path}")

    def get_database_statistics(self) -> Dict[str, Any]:
        """
        Get various statistics about the database.

        :return: Dictionary containing database statistics
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            stats = {}

            # Total number of history entries
            cursor.execute('SELECT COUNT(*) FROM history')
            stats['total_history_entries'] = cursor.fetchone()[0]

            # Total number of bookmarks
            cursor.execute('SELECT COUNT(*) FROM bookmarks')
            stats['total_bookmarks'] = cursor.fetchone()[0]

            # Number of cached pages
            cursor.execute('SELECT COUNT(*) FROM cache')
            stats['cached_pages'] = cursor.fetchone()[0]

            # Database size
            stats['database_size_bytes'] = self.get_database_size()

            # Most recent visit
            cursor.execute('SELECT MAX(visit_time) FROM history')
            stats['most_recent_visit'] = cursor.fetchone()[0]

            return stats

    def __del__(self):
        """
        Destructor to ensure the database connection is closed when the object is destroyed.
        """
        if self.conn:
            self.conn.close()
            logger.debug("Database connection closed")

# Usage example:
if __name__ == "__main__":
    db = AluminumDatabase()
    
    # Add some sample data
    db.add_history_entry("https://www.example.com", "Example Website")
    db.add_bookmark("https://www.python.org", "Python Official Website")
    db.update_setting("theme", "dark")
    
    # Retrieve and print some data
    print("Recent History:")
    for entry in db.get_history(limit=5):
        print(f"- {entry['title']} ({entry['url']})")
    
    print("\nBookmarks:")
    for bookmark in db.get_bookmarks():
        print(f"- {bookmark['title']} ({bookmark['url']})")
    
    print(f"\nTheme setting: {db.get_setting('theme')}")
    
    # Print database statistics
    stats = db.get_database_statistics()
    print("\nDatabase Statistics:")
    for key, value in stats.items():
        print(f"{key}: {value}")

    # Optimize the database
    db.optimize_database()

    logger.info("Database operations completed successfully")
