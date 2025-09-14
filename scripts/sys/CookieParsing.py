
import re
from typing import Dict, List, Optional, Union
from urllib.parse import unquote
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CookieParser:
    """
    A comprehensive cookie parsing class for the Aluminum web browser.
    This class provides methods to parse, validate, and manage HTTP cookies.
    """

    def __init__(self):
        """
        Initialize the CookieParser with default attributes.
        """
        self.cookie_jar: Dict[str, Dict[str, Union[str, datetime]]] = {}
        self.max_cookie_size: int = 4096  # Maximum size of a single cookie in bytes
        self.max_cookies_per_domain: int = 50  # Maximum number of cookies per domain

    def parse_cookie_string(self, cookie_string: str) -> Dict[str, str]:
        """
        Parse a cookie string and return a dictionary of key-value pairs.

        Args:
            cookie_string (str): The raw cookie string from the HTTP header.

        Returns:
            Dict[str, str]: A dictionary containing parsed cookie key-value pairs.
        """
        cookie_dict = {}
        try:
            pairs = re.split(r';\s*', cookie_string)
            for pair in pairs:
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    cookie_dict[key.strip()] = unquote(value.strip())
                else:
                    cookie_dict[pair.strip()] = None
        except Exception as e:
            logger.error(f"Error parsing cookie string: {e}")
        return cookie_dict

    def validate_cookie(self, name: str, value: str, domain: str) -> bool:
        """
        Validate a cookie based on various security and size constraints.

        Args:
            name (str): The name of the cookie.
            value (str): The value of the cookie.
            domain (str): The domain associated with the cookie.

        Returns:
            bool: True if the cookie is valid, False otherwise.
        """
        # Check cookie size
        if len(name) + len(value) > self.max_cookie_size:
            logger.warning(f"Cookie '{name}' exceeds maximum size for domain '{domain}'")
            return False

        # Check number of cookies per domain
        if domain in self.cookie_jar and len(self.cookie_jar[domain]) >= self.max_cookies_per_domain:
            logger.warning(f"Maximum number of cookies reached for domain '{domain}'")
            return False

        # Additional security checks can be implemented here
        # For example, checking for secure flag, HttpOnly flag, etc.

        return True

    def set_cookie(self, name: str, value: str, domain: str, expires: Optional[str] = None, 
                   path: str = '/', secure: bool = False, http_only: bool = False) -> None:
        """
        Set a cookie in the cookie jar.

        Args:
            name (str): The name of the cookie.
            value (str): The value of the cookie.
            domain (str): The domain associated with the cookie.
            expires (Optional[str]): The expiration date of the cookie (RFC 1123 format).
            path (str): The path for which the cookie is valid.
            secure (bool): Whether the cookie should only be transmitted over secure connections.
            http_only (bool): Whether the cookie should be accessible only through HTTP(S).
        """
        if not self.validate_cookie(name, value, domain):
            return

        if domain not in self.cookie_jar:
            self.cookie_jar[domain] = {}

        cookie_data = {
            'value': value,
            'path': path,
            'secure': secure,
            'http_only': http_only
        }

        if expires:
            try:
                expiry_date = datetime.strptime(expires, "%a, %d %b %Y %H:%M:%S GMT")
                cookie_data['expires'] = expiry_date
            except ValueError:
                logger.error(f"Invalid expiration date format for cookie '{name}': {expires}")

        self.cookie_jar[domain][name] = cookie_data
        logger.info(f"Cookie '{name}' set for domain '{domain}'")

    def get_cookie(self, name: str, domain: str) -> Optional[str]:
        """
        Retrieve a cookie value from the cookie jar.

        Args:
            name (str): The name of the cookie.
            domain (str): The domain associated with the cookie.

        Returns:
            Optional[str]: The cookie value if found, None otherwise.
        """
        if domain in self.cookie_jar and name in self.cookie_jar[domain]:
            cookie_data = self.cookie_jar[domain][name]
            if 'expires' in cookie_data and cookie_data['expires'] < datetime.utcnow():
                del self.cookie_jar[domain][name]
                logger.info(f"Expired cookie '{name}' removed for domain '{domain}'")
                return None
            return cookie_data['value']
        return None

    def delete_cookie(self, name: str, domain: str) -> None:
        """
        Delete a cookie from the cookie jar.

        Args:
            name (str): The name of the cookie to delete.
            domain (str): The domain associated with the cookie.
        """
        if domain in self.cookie_jar and name in self.cookie_jar[domain]:
            del self.cookie_jar[domain][name]
            logger.info(f"Cookie '{name}' deleted for domain '{domain}'")

    def clear_cookies(self, domain: Optional[str] = None) -> None:
        """
        Clear all cookies or cookies for a specific domain.

        Args:
            domain (Optional[str]): The domain for which to clear cookies. If None, clear all cookies.
        """
        if domain:
            if domain in self.cookie_jar:
                del self.cookie_jar[domain]
                logger.info(f"All cookies cleared for domain '{domain}'")
        else:
            self.cookie_jar.clear()
            logger.info("All cookies cleared from the cookie jar")

    def get_cookies_for_url(self, url: str) -> List[Dict[str, str]]:
        """
        Get all relevant cookies for a given URL.

        Args:
            url (str): The URL for which to retrieve cookies.

        Returns:
            List[Dict[str, str]]: A list of dictionaries containing cookie information.
        """
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path

        relevant_cookies = []
        domains_to_check = [domain]
        while '.' in domain:
            domain = domain.split('.', 1)[1]
            domains_to_check.append(domain)

        for check_domain in domains_to_check:
            if check_domain in self.cookie_jar:
                for name, cookie_data in self.cookie_jar[check_domain].items():
                    if cookie_data['path'] == '/' or path.startswith(cookie_data['path']):
                        if 'expires' not in cookie_data or cookie_data['expires'] > datetime.utcnow():
                            relevant_cookies.append({
                                'name': name,
                                'value': cookie_data['value'],
                                'domain': check_domain,
                                'path': cookie_data['path']
                            })

        return relevant_cookies

    def serialize_cookies(self) -> str:
        """
        Serialize the cookie jar for storage or transmission.

        Returns:
            str: A JSON string representation of the cookie jar.
        """
        import json

        serializable_jar = {}
        for domain, cookies in self.cookie_jar.items():
            serializable_jar[domain] = {}
            for name, cookie_data in cookies.items():
                serializable_cookie = cookie_data.copy()
                if 'expires' in serializable_cookie:
                    serializable_cookie['expires'] = serializable_cookie['expires'].isoformat()
                serializable_jar[domain][name] = serializable_cookie

        return json.dumps(serializable_jar, indent=2)

    def deserialize_cookies(self, serialized_cookies: str) -> None:
        """
        Deserialize and load cookies into the cookie jar.

        Args:
            serialized_cookies (str): A JSON string representation of cookies to load.
        """
        import json

        try:
            loaded_jar = json.loads(serialized_cookies)
            for domain, cookies in loaded_jar.items():
                if domain not in self.cookie_jar:
                    self.cookie_jar[domain] = {}
                for name, cookie_data in cookies.items():
                    if 'expires' in cookie_data:
                        cookie_data['expires'] = datetime.fromisoformat(cookie_data['expires'])
                    self.cookie_jar[domain][name] = cookie_data
            logger.info("Cookies successfully deserialized and loaded into the cookie jar")
        except json.JSONDecodeError as e:
            logger.error(f"Error deserializing cookies: {e}")

    def handle_set_cookie_header(self, header_value: str, domain: str) -> None:
        """
        Handle the Set-Cookie header from an HTTP response.

        Args:
            header_value (str): The value of the Set-Cookie header.
            domain (str): The domain associated with the cookie.
        """
        parts = header_value.split(';')
        if not parts:
            return

        name_value = parts[0].strip().split('=', 1)
        if len(name_value) != 2:
            return

        name, value = name_value
        cookie_data = {
            'value': unquote(value),
            'domain': domain,
            'path': '/',
            'secure': False,
            'http_only': False
        }

        for part in parts[1:]:
            part = part.strip().lower()
            if part == 'secure':
                cookie_data['secure'] = True
            elif part == 'httponly':
                cookie_data['http_only'] = True
            elif part.startswith('expires='):
                try:
                    expires = part.split('=', 1)[1]
                    cookie_data['expires'] = datetime.strptime(expires, "%a, %d %b %Y %H:%M:%S GMT")
                except ValueError:
                    logger.warning(f"Invalid expires date in Set-Cookie header: {expires}")
            elif part.startswith('max-age='):
                try:
                    max_age = int(part.split('=', 1)[1])
                    cookie_data['expires'] = datetime.utcnow() + timedelta(seconds=max_age)
                except ValueError:
                    logger.warning(f"Invalid max-age in Set-Cookie header: {part}")
            elif part.startswith('domain='):
                cookie_data['domain'] = part.split('=', 1)[1]
            elif part.startswith('path='):
                cookie_data['path'] = part.split('=', 1)[1]

        self.set_cookie(name, cookie_data['value'], cookie_data['domain'],
                        expires=cookie_data['expires'].strftime("%a, %d %b %Y %H:%M:%S GMT") if 'expires' in cookie_data else None,
                        path=cookie_data['path'],
                        secure=cookie_data['secure'],
                        http_only=cookie_data['http_only'])

    def generate_cookie_header(self, url: str) -> str:
        """
        Generate the Cookie header value for an HTTP request.

        Args:
            url (str): The URL for which to generate the Cookie header.

        Returns:
            str: The Cookie header value.
        """
        cookies = self.get_cookies_for_url(url)
        return '; '.join([f"{cookie['name']}={cookie['value']}" for cookie in cookies])

    def cleanup_expired_cookies(self) -> None:
        """
        Remove all expired cookies from the cookie jar.
        """
        current_time = datetime.utcnow()
        domains_to_remove = []

        for domain, cookies in self.cookie_jar.items():
            cookies_to_remove = []
            for name, cookie_data in cookies.items():
                if 'expires' in cookie_data and cookie_data['expires'] < current_time:
                    cookies_to_remove.append(name)
            
            for name in cookies_to_remove:
                del cookies[name]
                logger.info(f"Expired cookie '{name}' removed for domain '{domain}'")
            
            if not cookies:
                domains_to_remove.append(domain)

        for domain in domains_to_remove:
            del self.cookie_jar[domain]
            logger.info(f"Empty domain '{domain}' removed from cookie jar")

    def is_third_party_cookie(self, cookie_domain: str, request_domain: str) -> bool:
        """
        Determine if a cookie is a third-party cookie.

        Args:
            cookie_domain (str): The domain of the cookie.
            request_domain (str): The domain of the current request.

        Returns:
            bool: True if it's a third-party cookie, False otherwise.
        """
        return not (cookie_domain == request_domain or request_domain.endswith('.' + cookie_domain))

    def apply_cookie_policy(self, policy: Dict[str, bool]) -> None:
        """
        Apply a cookie policy to the current cookie jar.

        Args:
            policy (Dict[str, bool]): A dictionary representing the cookie policy.
                Keys can include 'accept_all', 'block_third_party', 'block_all'.
        """
        if policy.get('block_all', False):
            self.clear_cookies()
            logger.info("All cookies blocked as per policy")
        elif policy.get('block_third_party', False):
            current_domains = list(self.cookie_jar.keys())
            for domain in current_domains:
                if self.is_third_party_cookie(domain, domain):  # Simplified check
                    del self.cookie_jar[domain]
                    logger.info(f"Third-party cookies for domain '{domain}' blocked as per policy")
        elif not policy.get('accept_all', True):
            logger.warning("Invalid cookie policy configuration")

    def get_cookie_stats(self) -> Dict[str, int]:
        """
        Get statistics about the current state of the cookie jar.

        Returns:
            Dict[str, int]: A dictionary containing cookie statistics.
        """
        total_cookies = sum(len(cookies) for cookies in self.cookie_jar.values())
        return {
            'total_cookies': total_cookies,
            'total_domains': len(self.cookie_jar),
            'avg_cookies_per_domain': total_cookies // len(self.cookie_jar) if self.cookie_jar else 0
        }

    def export_cookies_to_netscape_format(self, file_path: str) -> None:
        """
        Export cookies to a Netscape format cookie file.

        Args:
            file_path (str): The path to the file where cookies will be exported.
        """
        with open(file_path, 'w') as f:
            f.write("# Netscape HTTP Cookie File\n")
            for domain, cookies in self.cookie_jar.items():
                for name, cookie_data in cookies.items():
                    secure = "TRUE" if cookie_data.get('secure', False) else "FALSE"
                    http_only = "TRUE" if cookie_data.get('http_only', False) else "FALSE"
                    expires = cookie_data.get('expires', datetime.max).strftime("%s")
                    path = cookie_data.get('path', '/')
                    f.write(f"{domain}\tTRUE\t{path}\t{secure}\t{expires}\t{name}\t{cookie_data['value']}\n")