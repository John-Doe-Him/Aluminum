
import os
import sqlite3
import json
import datetime
import shutil
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

class AluminumBrowserHistory:
    """
    A class to handle browser history for the Aluminum browser.
    This class provides functionality to interact with, manage, and analyze browser history.
    """

    def __init__(self, profile_path: str):
        """
        Initialize the AluminumBrowserHistory object.

        Args:
            profile_path (str): Path to the Aluminum browser profile directory.
        """
        self.profile_path = profile_path
        self.history_db_path = os.path.join(profile_path, 'History')
        self.backup_db_path = os.path.join(profile_path, 'History_backup')
        self.connection = None
        self.cursor = None

    def __enter__(self):
        """
        Context manager entry point. Establishes database connection.

        Returns:
            AluminumBrowserHistory: The current instance.
        """
        self._create_connection()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit point. Closes database connection.

        Args:
            exc_type: Exception type if an exception was raised.
            exc_val: Exception value if an exception was raised.
            exc_tb: Exception traceback if an exception was raised.
        """
        self._close_connection()

    def _create_connection(self):
        """
        Create a connection to the SQLite database containing browser history.
        """
        # Create a backup of the database to avoid locked database issues
        shutil.copy2(self.history_db_path, self.backup_db_path)
        self.connection = sqlite3.connect(self.backup_db_path)
        self.cursor = self.connection.cursor()

    def _close_connection(self):
        """
        Close the database connection and remove the backup file.
        """
        if self.connection:
            self.connection.close()
        if os.path.exists(self.backup_db_path):
            os.remove(self.backup_db_path)

    def get_history(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Retrieve browser history entries.

        Args:
            limit (int): Maximum number of entries to retrieve. Defaults to 100.
            offset (int): Number of entries to skip. Defaults to 0.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries containing history entries.
        """
        query = """
        SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.last_visit_time
        FROM urls
        ORDER BY urls.last_visit_time DESC
        LIMIT ? OFFSET ?
        """
        self.cursor.execute(query, (limit, offset))
        rows = self.cursor.fetchall()

        history = []
        for row in rows:
            history.append({
                'id': row[0],
                'url': row[1],
                'title': row[2],
                'visit_count': row[3],
                'last_visit_time': self._convert_chrome_time(row[4])
            })

        return history

    def search_history(self, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search browser history for entries containing the given keyword.

        Args:
            keyword (str): Keyword to search for in URLs and titles.
            limit (int): Maximum number of entries to retrieve. Defaults to 100.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries containing matching history entries.
        """
        query = """
        SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.last_visit_time
        FROM urls
        WHERE urls.url LIKE ? OR urls.title LIKE ?
        ORDER BY urls.last_visit_time DESC
        LIMIT ?
        """
        search_term = f'%{keyword}%'
        self.cursor.execute(query, (search_term, search_term, limit))
        rows = self.cursor.fetchall()

        results = []
        for row in rows:
            results.append({
                'id': row[0],
                'url': row[1],
                'title': row[2],
                'visit_count': row[3],
                'last_visit_time': self._convert_chrome_time(row[4])
            })

        return results

    def get_most_visited_sites(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieve the most frequently visited sites.

        Args:
            limit (int): Maximum number of sites to retrieve. Defaults to 10.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries containing the most visited sites.
        """
        query = """
        SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.last_visit_time
        FROM urls
        ORDER BY urls.visit_count DESC
        LIMIT ?
        """
        self.cursor.execute(query, (limit,))
        rows = self.cursor.fetchall()

        most_visited = []
        for row in rows:
            most_visited.append({
                'id': row[0],
                'url': row[1],
                'title': row[2],
                'visit_count': row[3],
                'last_visit_time': self._convert_chrome_time(row[4])
            })

        return most_visited

    def get_browsing_stats(self) -> Dict[str, Any]:
        """
        Generate browsing statistics.

        Returns:
            Dict[str, Any]: A dictionary containing various browsing statistics.
        """
        stats = {}

        # Total number of URLs visited
        self.cursor.execute("SELECT COUNT(*) FROM urls")
        stats['total_urls'] = self.cursor.fetchone()[0]

        # Total number of visits
        self.cursor.execute("SELECT SUM(visit_count) FROM urls")
        stats['total_visits'] = self.cursor.fetchone()[0]

        # Average visits per URL
        stats['avg_visits_per_url'] = stats['total_visits'] / stats['total_urls'] if stats['total_urls'] > 0 else 0

        # Most recent visit
        self.cursor.execute("SELECT MAX(last_visit_time) FROM urls")
        stats['most_recent_visit'] = self._convert_chrome_time(self.cursor.fetchone()[0])

        # Oldest visit
        self.cursor.execute("SELECT MIN(last_visit_time) FROM urls")
        stats['oldest_visit'] = self._convert_chrome_time(self.cursor.fetchone()[0])

        return stats

    def delete_history_entry(self, url_id: int) -> bool:
        """
        Delete a specific history entry.

        Args:
            url_id (int): The ID of the URL entry to delete.

        Returns:
            bool: True if the entry was successfully deleted, False otherwise.
        """
        try:
            self.cursor.execute("DELETE FROM urls WHERE id = ?", (url_id,))
            self.connection.commit()
            return True
        except sqlite3.Error:
            return False

    def clear_history(self) -> bool:
        """
        Clear all browsing history.

        Returns:
            bool: True if the history was successfully cleared, False otherwise.
        """
        try:
            self.cursor.execute("DELETE FROM urls")
            self.connection.commit()
            return True
        except sqlite3.Error:
            return False

    def export_history(self, output_file: str, format: str = 'json') -> bool:
        """
        Export browsing history to a file.

        Args:
            output_file (str): Path to the output file.
            format (str): Export format, either 'json' or 'csv'. Defaults to 'json'.

        Returns:
            bool: True if the export was successful, False otherwise.
        """
        history = self.get_history(limit=0)  # Get all history entries

        try:
            if format.lower() == 'json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(history, f, ensure_ascii=False, indent=4)
            elif format.lower() == 'csv':
                import csv
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=['id', 'url', 'title', 'visit_count', 'last_visit_time'])
                    writer.writeheader()
                    writer.writerows(history)
            else:
                raise ValueError("Unsupported export format. Use 'json' or 'csv'.")
            return True
        except (IOError, ValueError):
            return False

    def analyze_domain_visits(self) -> Dict[str, int]:
        """
        Analyze the number of visits per domain.

        Returns:
            Dict[str, int]: A dictionary with domains as keys and visit counts as values.
        """
        query = "SELECT url, visit_count FROM urls"
        self.cursor.execute(query)
        rows = self.cursor.fetchall()

        domain_visits = {}
        for row in rows:
            url, visit_count = row
            domain = urlparse(url).netloc
            domain_visits[domain] = domain_visits.get(domain, 0) + visit_count

        return dict(sorted(domain_visits.items(), key=lambda x: x[1], reverse=True))

    def get_visit_timeline(self, start_date: Optional[datetime.date] = None, end_date: Optional[datetime.date] = None) -> Dict[str, int]:
        """
        Get a timeline of visits within a specified date range.

        Args:
            start_date (Optional[datetime.date]): Start date for the timeline. Defaults to None (earliest date).
            end_date (Optional[datetime.date]): End date for the timeline. Defaults to None (latest date).

        Returns:
            Dict[str, int]: A dictionary with dates as keys and visit counts as values.
        """
        query = """
        SELECT DATE(last_visit_time / 1000000 - 11644473600, 'unixepoch') as visit_date, COUNT(*) as visit_count
        FROM urls
        WHERE 1=1
        """
        params = []

        if start_date:
            query += " AND last_visit_time >= ?"
            params.append(self._convert_datetime_to_chrome_time(start_date))
        if end_date:
            query += " AND last_visit_time <= ?"
            params.append(self._convert_datetime_to_chrome_time(end_date))

        query += " GROUP BY visit_date ORDER BY visit_date"

        self.cursor.execute(query, params)
        rows = self.cursor.fetchall()

        timeline = {row[0]: row[1] for row in rows}
        return timeline

    @staticmethod
    def _convert_chrome_time(chrome_timestamp: int) -> datetime.datetime:
        """
        Convert Chrome timestamp to Python datetime object.

        Args:
            chrome_timestamp (int): Chrome timestamp in microseconds.

        Returns:
            datetime.datetime: Converted datetime object.
        """
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=chrome_timestamp)

    @staticmethod
    def _convert_datetime_to_chrome_time(dt: datetime.datetime) -> int:
        """
        Convert Python datetime object to Chrome timestamp.

        Args:
            dt (datetime.datetime): Python datetime object.

        Returns:
            int: Chrome timestamp in microseconds.
        """
        delta = dt - datetime.datetime(1601, 1, 1)
        return int(delta.total_seconds() * 1000000)

# Example usage:
if __name__ == "__main__":
    profile_path = r"C:\Users\YourUsername\AppData\Local\Aluminum\User Data\Default"
    
    with AluminumBrowserHistory(profile_path) as history:
        # Get recent history
        recent_history = history.get_history(limit=10)
        print("Recent History:")
        for entry in recent_history:
            print(f"{entry['title']} - {entry['url']}")

        # Search history
        search_results = history.search_history("python")
        print("\nSearch Results for 'python':")
        for entry in search_results:
            print(f"{entry['title']} - {entry['url']}")

        # Get most visited sites
        most_visited = history.get_most_visited_sites()
        print("\nMost Visited Sites:")
        for entry in most_visited:
            print(f"{entry['title']} - {entry['url']} (Visits: {entry['visit_count']})")

        # Get browsing stats
        stats = history.get_browsing_stats()
        print("\nBrowsing Statistics:")
        for key, value in stats.items():
            print(f"{key}: {value}")

        # Analyze domain visits
        domain_visits = history.analyze_domain_visits()
        print("\nTop 5 Most Visited Domains:")
        for domain, visits in list(domain_visits.items())[:5]:
            print(f"{domain}: {visits} visits")

        # Get visit timeline for the last 7 days
        end_date = datetime.date.today()
        start_date = end_date - datetime.timedelta(days=7)
        timeline = history.get_visit_timeline(start_date, end_date)
        print("\nVisit Timeline (Last 7 Days):")
        for date, count in timeline.items():
            print(f"{date}: {count} visits")

        # Export history to JSON
        if history.export_history("aluminum_history_export.json"):
            print("\nHistory exported successfully to aluminum_history_export.json")
        else:
            print("\nFailed to export history")

# Note: This example assumes the existence of an Aluminum browser with a similar
# history database structure. Adjustments may be needed based on the
# actual implementation of the Aluminum browser.
