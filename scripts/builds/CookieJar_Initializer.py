# cookie jar initalizment.
# made on 9/8/2024
# Author: Karim Sar

'''
 -o \
 -v \
 
 cookiejar {///} cookie.jar
'''
"""
Cookie Jar Management System for Web Browser Cookies
=====================================================

This module provides a comprehensive implementation of a cookie jar management system for web browser cookies.
It allows users to create a cookie jar, add cookies, remove cookies, count the number of cookies, and manage cookie expiration.

Author: Karim Sar
Date: 9/8/2024
"""

import datetime

class Cookie:
    """
    Represents a single cookie in the cookie jar.

    Attributes:
        name (str): The name of the cookie.
        value (str): The value of the cookie.
        domain (str): The domain of the cookie.
        path (str): The path of the cookie.
        expires (datetime): The expiration date of the cookie.
    """

    def __init__(self, name, value, domain, path, expires=None):
        """
        Initializes a new cookie.

        Args:
            name (str): The name of the cookie.
            value (str): The value of the cookie.
            domain (str): The domain of the cookie.
            path (str): The path of the cookie.
            expires (datetime, optional): The expiration date of the cookie. Defaults to None.
        """
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.expires = expires if expires else datetime.datetime.max

    def __str__(self):
        """
        Returns a string representation of the cookie.

        Returns:
            str: A string representation of the cookie.
        """
        return f"{self.name}={self.value}; Domain={self.domain}; Path={self.path}; Expires={self.expires}"


class CookieJar:
    """
    Represents a cookie jar.

    Attributes:
        cookies (dict): A dictionary of cookies in the jar, keyed by domain and path.
    """

    def __init__(self):
        """
        Initializes a new cookie jar.
        """
        self.cookies = {}

    def add_cookie(self, cookie):
        """
        Adds a cookie to the jar.

        Args:
            cookie (Cookie): The cookie to add.
        """
        if cookie.domain not in self.cookies:
            self.cookies[cookie.domain] = {}
        self.cookies[cookie.domain][cookie.path] = cookie

    def remove_cookie(self, domain, path, name):
        """
        Removes a cookie from the jar.

        Args:
            domain (str): The domain of the cookie.
            path (str): The path of the cookie.
            name (str): The name of the cookie.

        Raises:
            ValueError: If the cookie is not in the jar.
        """
        if domain in self.cookies and path in self.cookies[domain]:
            if name in [c.name for c in self.cookies[domain][path]]:
                del self.cookies[domain][path]
                if not self.cookies[domain]:
                    del self.cookies[domain]
            else:
                raise ValueError("Cookie not found in the jar")
        else:
            raise ValueError("Cookie not found in the jar")

    def count_cookies(self):
        """
        Returns the number of cookies in the jar.

        Returns:
            int: The number of cookies in the jar.
        """
        count = 0
        for domain in self.cookies.values():
            for path in domain.values():
                count += 1
        return count

    def get_cookies(self, domain=None, path=None):
        """
        Returns a list of cookies in the jar.

        Args:
            domain (str, optional): The domain of the cookies to retrieve. Defaults to None.
            path (str, optional): The path of the cookies to retrieve. Defaults to None.

        Returns:
            list: A list of cookies in the jar.
        """
        cookies = []
        if domain and path:
            if domain in self.cookies and path in self.cookies[domain]:
                cookies.append(self.cookies[domain][path])
        elif domain:
            if domain in self.cookies:
                for path in self.cookies[domain].values():
                    cookies.append(path)
        else:
            for domain in self.cookies.values():
                for path in domain.values():
                    cookies.append(path)
        return cookies

    def sort_cookies(self, key):
        """
        Sorts the cookies in the jar based on the given key.

        Args:
            key (str): The key to sort by. Can be 'name', 'value', 'domain', 'path', or 'expires'.
        """
        if key == 'name':
            for domain in self.cookies.values():
                for path in domain.values():
                    domain[path] = sorted(domain[path], key=lambda x: x.name)
        elif key == 'value':
            for domain in self.cookies.values():
                for path in domain.values():
                    domain[path] = sorted(domain[path], key=lambda x: x.value)
        elif key == 'domain':
            self.cookies = dict