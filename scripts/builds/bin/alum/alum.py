# alum.py
'''
  42bit integration, and initalizing app utility and .ts files into the program
  making ts a web and making its packages initalize into 1 tslib.
'''

import os
from typing import List

def initialize_ts_packages(packages: List[str]) -> None:
    # Initialize tslib
    if not os.path.exists('tslib'):
        os.makedirs('tslib')

    # Initialize packages
    for package in packages:
        package_path = os.path.join('tslib', package)
        if not os.path.exists(package_path):
            os.makedirs(package_path)

# Example usage
packages = ["\n"]
initialize_ts_packages(packages)