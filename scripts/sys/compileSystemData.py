
import os
import sys
import json
import logging
import platform
import psutil
import requests
import sqlite3
from datetime import datetime
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
ALUMINUM_VERSION = "1.0.0"
DATA_DIR = os.path.join(os.path.expanduser("~"), ".aluminum")
DB_PATH = os.path.join(DATA_DIR, "aluminum_data.db")
API_ENDPOINT = "https://api.aluminum.browser/system-data"

class SystemDataCompiler:
    def __init__(self):
        self.system_data: Dict[str, Any] = {}
        self.db_connection: sqlite3.Connection = None

    def compile_system_data(self) -> None:
        """
        Main method to compile all system data for Aluminum browser.
        """
        logger.info("Starting system data compilation for Aluminum browser...")
        
        self._ensure_data_directory()
        self._initialize_database()
        
        self._collect_hardware_info()
        self._collect_os_info()
        self._collect_network_info()
        self._collect_browser_info()
        self._collect_performance_metrics()
        
        self._save_to_database()
        self._upload_to_server()
        
        logger.info("System data compilation completed successfully.")

    def _ensure_data_directory(self) -> None:
        """
        Ensure that the data directory exists.
        """
        os.makedirs(DATA_DIR, exist_ok=True)
        logger.debug(f"Data directory ensured: {DATA_DIR}")

    def _initialize_database(self) -> None:
        """
        Initialize the SQLite database connection and create necessary tables.
        """
        try:
            self.db_connection = sqlite3.connect(DB_PATH)
            cursor = self.db_connection.cursor()
            
            # Create table for system data
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    data JSON
                )
            ''')
            
            self.db_connection.commit()
            logger.debug("Database initialized successfully.")
        except sqlite3.Error as e:
            logger.error(f"Error initializing database: {e}")
            sys.exit(1)

    def _collect_hardware_info(self) -> None:
        """
        Collect hardware information of the system.
        """
        logger.info("Collecting hardware information...")
        
        self.system_data['hardware'] = {
            'cpu': {
                'brand': platform.processor(),
                'cores': psutil.cpu_count(logical=False),
                'threads': psutil.cpu_count(logical=True),
                'frequency': psutil.cpu_freq().current
            },
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'free': psutil.disk_usage('/').free
            },
            'gpu': self._get_gpu_info()
        }
        
        logger.debug("Hardware information collected successfully.")

    def _get_gpu_info(self) -> Dict[str, str]:
        """
        Attempt to retrieve GPU information.
        """
        try:
            import GPUtil
            gpus = GPUtil.getGPUs()
            if gpus:
                gpu = gpus[0]  # Assuming we're interested in the first GPU
                return {
                    'name': gpu.name,
                    'memory_total': gpu.memoryTotal,
                    'memory_used': gpu.memoryUsed,
                    'load': gpu.load
                }
        except ImportError:
            logger.warning("GPUtil not installed. GPU information not available.")
        except Exception as e:
            logger.error(f"Error retrieving GPU information: {e}")
        
        return {'error': 'GPU information not available'}

    def _collect_os_info(self) -> None:
        """
        Collect operating system information.
        """
        logger.info("Collecting operating system information...")
        
        self.system_data['os'] = {
            'name': platform.system(),
            'version': platform.version(),
            'release': platform.release(),
            'architecture': platform.machine(),
            'python_version': platform.python_version()
        }
        
        logger.debug("Operating system information collected successfully.")

    def _collect_network_info(self) -> None:
        """
        Collect network-related information.
        """
        logger.info("Collecting network information...")
        
        self.system_data['network'] = {
            'hostname': platform.node(),
            'ip_address': self._get_ip_address(),
            'mac_address': self._get_mac_address(),
            'network_interfaces': psutil.net_if_addrs()
        }
        
        logger.debug("Network information collected successfully.")

    def _get_ip_address(self) -> str:
        """
        Retrieve the system's public IP address.
        """
        try:
            response = requests.get('https://api.ipify.org')
            return response.text
        except requests.RequestException:
            logger.warning("Failed to retrieve public IP address.")
            return "Unknown"

    def _get_mac_address(self) -> str:
        """
        Retrieve the MAC address of the first non-loopback network interface.
        """
        for interface, addrs in psutil.net_if_addrs().items():
            if interface != 'lo':
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:
                        return addr.address
        return "Unknown"

    def _collect_browser_info(self) -> None:
        """
        Collect Aluminum browser-specific information.
        """
        logger.info("Collecting Aluminum browser information...")
        
        self.system_data['browser'] = {
            'name': 'Aluminum',
            'version': ALUMINUM_VERSION,
            'user_agent': self._generate_user_agent(),
            'plugins': self._get_installed_plugins(),
            'extensions': self._get_installed_extensions()
        }
        
        logger.debug("Browser information collected successfully.")

    def _generate_user_agent(self) -> str:
        """
        Generate a user agent string for Aluminum browser.
        """
        return f"Aluminum/{ALUMINUM_VERSION} ({platform.system()} {platform.release()}; {platform.machine()}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    def _get_installed_plugins(self) -> List[Dict[str, str]]:
        """
        Retrieve information about installed plugins (placeholder implementation).
        """
        # In a real implementation, this would query the browser's plugin system
        return [
            {'name': 'Adobe Flash Player', 'version': '32.0.0.465'},
            {'name': 'QuickTime Player', 'version': '7.7.9'}
        ]

    def _get_installed_extensions(self) -> List[Dict[str, str]]:
        """
        Retrieve information about installed extensions (placeholder implementation).
        """
        # In a real implementation, this would query the browser's extension system
        return [
            {'name': 'Aluminum AdBlocker', 'version': '1.2.3', 'enabled': True},
            {'name': 'Aluminum Password Manager', 'version': '2.0.1', 'enabled': True}
        ]

    def _collect_performance_metrics(self) -> None:
        """
        Collect various performance metrics of the system.
        """
        logger.info("Collecting performance metrics...")
        
        self.system_data['performance'] = {
            'cpu_usage': psutil.cpu_percent(interval=1),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_io': self._get_disk_io_stats(),
            'network_io': self._get_network_io_stats(),
            'battery': self._get_battery_info()
        }
        
        logger.debug("Performance metrics collected successfully.")

    def _get_disk_io_stats(self) -> Dict[str, float]:
        """
        Retrieve disk I/O statistics.
        """
        disk_io = psutil.disk_io_counters()
        return {
            'read_bytes': disk_io.read_bytes,
            'write_bytes': disk_io.write_bytes,
            'read_count': disk_io.read_count,
            'write_count': disk_io.write_count
        }

    def _get_network_io_stats(self) -> Dict[str, float]:
        """
        Retrieve network I/O statistics.
        """
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }

    def _get_battery_info(self) -> Dict[str, Any]:
        """
        Retrieve battery information if available.
        """
        try:
            battery = psutil.sensors_battery()
            if battery:
                return {
                    'percent': battery.percent,
                    'power_plugged': battery.power_plugged,
                    'time_left': battery.secsleft
                }
        except AttributeError:
            logger.warning("Battery information not available on this system.")
        return {'error': 'Battery information not available'}

    def _save_to_database(self) -> None:
        """
        Save the compiled system data to the SQLite database.
        """
        logger.info("Saving system data to database...")
        
        try:
            cursor = self.db_connection.cursor()
            timestamp = datetime.now().isoformat()
            data_json = json.dumps(self.system_data)
            
            cursor.execute('''
                INSERT INTO system_data (timestamp, data)
                VALUES (?, ?)
            ''', (timestamp, data_json))
            
            self.db_connection.commit()
            logger.debug("System data saved to database successfully.")
        except sqlite3.Error as e:
            logger.error(f"Error saving data to database: {e}")

    def _upload_to_server(self) -> None:
        """
        Upload the compiled system data to the Aluminum server.
        """
        logger.info("Uploading system data to Aluminum server...")
        
        try:
            response = requests.post(API_ENDPOINT, json=self.system_data)
            response.raise_for_status()
            logger.debug("System data uploaded to server successfully.")
        except requests.RequestException as e:
            logger.error(f"Error uploading data to server: {e}")

    def __del__(self):
        """
        Destructor to ensure proper closure of database connection.
        """
        if self.db_connection:
            self.db_connection.close()
            logger.debug("Database connection closed.")

def main():
    """
    Main function to run the SystemDataCompiler.
    """
    compiler = SystemDataCompiler()
    compiler.compile_system_data()

if __name__ == "__main__":
    main()
