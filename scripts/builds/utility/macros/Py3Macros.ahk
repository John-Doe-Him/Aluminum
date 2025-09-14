; Python 3 Macros
; This script contains various macros and hotkeys for Python 3 development
; Author: Karim S
; Date: 9/7/2024
; Version: 1.0.0

#NoEnv  ; Recommended for performance and compatibility with future AutoHotkey releases.
#Warn  ; Enable warnings to assist with detecting common errors.
SendMode Input  ; Recommended for new scripts due to its superior speed and reliability.
SetWorkingDir %A_ScriptDir%  ; Ensures a consistent starting directory.

; Global variables
global pythonPath := "C:\Python39\python.exe"  ; Update this path to your Python 3 installation
global pipPath := "C:\Python39\Scripts\pip.exe"  ; Update this path to your pip installation

; Hotkey to run the current Python script
^!r::
    RunPythonScript()
return

; Hotkey to open Python REPL
^!p::
    OpenPythonREPL()
return

; Hotkey to insert Python function template
^!f::
    InsertPythonFunction()
return

; Hotkey to insert Python class template
^!c::
    InsertPythonClass()
return

; Hotkey to insert Python main block
^!m::
    InsertPythonMain()
return

; Hotkey to insert Python docstring
^!d::
    InsertPythonDocstring()
return

; Hotkey to insert Python list comprehension
^!l::
    InsertListComprehension()
return

; Hotkey to insert Python dictionary comprehension
^!k::
    InsertDictComprehension()
return

; Hotkey to insert Python try-except block
^!t::
    InsertTryExcept()
return

; Hotkey to insert Python with statement
^!w::
    InsertWithStatement()
return

; Hotkey to insert Python decorator
^!@::
    InsertDecorator()
return

; Hotkey to insert Python lambda function
^!\::
    InsertLambdaFunction()
return

; Hotkey to insert Python generator expression
^!g::
    InsertGeneratorExpression()
return

; Hotkey to insert Python f-string
^!s::
    InsertFString()
return

; Hotkey to insert Python type hints
^!h::
    InsertTypeHints()
return

; Hotkey to insert Python asyncio boilerplate
^!a::
    InsertAsyncioBoilerplate()
return

; Hotkey to insert Python unittest boilerplate
^!u::
    InsertUnittestBoilerplate()
return

; Hotkey to insert Python logging setup
^!o::
    InsertLoggingSetup()
return

; Hotkey to insert Python argparse setup
^!v::
    InsertArgparseSetup()
return

; Function to run the current Python script
RunPythonScript() {
    ; Get the current file path
    WinGetActiveTitle, activeTitle
    if (InStr(activeTitle, ".py")) {
        ; Extract the file path from the title
        filePath := RegExReplace(activeTitle, " - .*$")
        
        ; Run the Python script
        Run, %pythonPath% "%filePath%"
        
        ; Display a notification
        TrayTip, Python Script, Running %filePath%, 2
    } else {
        MsgBox, The active window does not appear to be a Python file.
    }
}

; Function to open Python REPL
OpenPythonREPL() {
    Run, %pythonPath%
}

; Function to insert Python function template
InsertPythonFunction() {
    SendInput,
    (
def function_name(param1: type1, param2: type2) -> return_type:
    """
    Function description.

    Args:
        param1 (type1): Description of param1.
        param2 (type2): Description of param2.

    Returns:
        return_type: Description of return value.

    Raises:
        ExceptionType: Description of when this exception is raised.
    """
    # Function body
    pass

    )
}

; Function to insert Python class template
InsertPythonClass() {
    SendInput,
    (
class ClassName:
    """
    Class description.

    Attributes:
        attr1 (type1): Description of attr1.
        attr2 (type2): Description of attr2.
    """

    def __init__(self, param1: type1, param2: type2):
        """
        Initialize the ClassName.

        Args:
            param1 (type1): Description of param1.
            param2 (type2): Description of param2.
        """
        self.attr1 = param1
        self.attr2 = param2

    def method_name(self, param: type) -> return_type:
        """
        Method description.

        Args:
            param (type): Description of param.

        Returns:
            return_type: Description of return value.
        """
        # Method body
        pass

    )
}

; Function to insert Python main block
InsertPythonMain() {
    SendInput,
    (
if __name__ == "__main__":
    # Main code block
    pass

    )
}

; Function to insert Python docstring
InsertPythonDocstring() {
    SendInput,
    (
"""
Description of the function/class/module.

Args:
    param1 (type1): Description of param1.
    param2 (type2): Description of param2.

Returns:
    return_type: Description of return value.

Raises:
    ExceptionType: Description of when this exception is raised.

Example:
    >>> example_usage()
    Expected output
"""

    )
}

; Function to insert Python list comprehension
InsertListComprehension() {
    SendInput, [expression for item in iterable if condition]
}

; Function to insert Python dictionary comprehension
InsertDictComprehension() {
    SendInput, {key_expression: value_expression for item in iterable if condition}
}

; Function to insert Python try-except block
InsertTryExcept() {
    SendInput,
    (
try:
    # Code that may raise an exception
    pass
except ExceptionType as e:
    # Handle the exception
    print(f"An error occurred: {e}")
else:
    # Code to run if no exception was raised
    pass
finally:
    # Code that will always run, regardless of whether an exception was raised
    pass

    )
}

; Function to insert Python with statement
InsertWithStatement() {
    SendInput,
    (
with open("filename.txt", "r") as file:
    content = file.read()
    # Process the content

    )
}

; Function to insert Python decorator
InsertDecorator() {
    SendInput,
    (
def decorator_name(func):
    def wrapper(*args, **kwargs):
        # Code to execute before the function
        result = func(*args, **kwargs)
        # Code to execute after the function
        return result
    return wrapper

@decorator_name
def function_name():
    pass

    )
}

; Function to insert Python lambda function
InsertLambdaFunction() {
    SendInput, lambda x: x * 2
}

; Function to insert Python generator expression
InsertGeneratorExpression() {
    SendInput, (expression for item in iterable if condition)
}

; Function to insert Python f-string
InsertFString() {
    SendInput, f"Text {variable} more text {expression}"
}

; Function to insert Python type hints
InsertTypeHints() {
    SendInput,
    (
from typing import List, Dict, Tuple, Optional, Union

def function_name(param1: int, param2: str) -> List[Dict[str, Union[int, str]]]:
    result: List[Dict[str, Union[int, str]]] = []
    # Function body
    return result

    )
}

; Function to insert Python asyncio boilerplate
InsertAsyncioBoilerplate() {
    SendInput,
    (
import asyncio

async def async_function():
    await asyncio.sleep(1)
    return "Result"

async def main():
    result = await async_function()
    print(result)

if __name__ == "__main__":
    asyncio.run(main())

    )
}

; Function to insert Python unittest boilerplate
InsertUnittestBoilerplate() {
    SendInput,
    (
import unittest

class TestClassName(unittest.TestCase):
    def setUp(self):
        # Set up test fixtures
        pass

    def tearDown(self):
        # Clean up after tests
        pass

    def test_method_name(self):
        # Test case
        self.assertEqual(expected, actual)

if __name__ == "__main__":
    unittest.main()

    )
}

; Function to insert Python logging setup
InsertLoggingSetup() {
    SendInput,
    (
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log',
    filemode='w'
)

# Create a logger
logger = logging.getLogger(__name__)

# Usage example
logger.info("This is an info message")
logger.warning("This is a warning message")
logger.error("This is an error message")

    )
}

; Function to insert Python argparse setup
InsertArgparseSetup() {
    SendInput,
    (
import argparse

def main():
    parser = argparse.ArgumentParser(description="Description of your program")
    parser.add_argument("-i", "--input", help="Input file path", required=True)
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
    args = parser.parse_args()

    # Access arguments
    input_file = args.input
    output_file = args.output
    verbose = args.verbose

    # Your program logic here
    if verbose:
        print(f"Input file: {input_file}")
        print(f"Output file: {output_file}")

if __name__ == "__main__":
    main()

    )
}

; Additional utility functions

; Function to check Python version
CheckPythonVersion() {
    RunWait, %pythonPath% --version,, Hide
    if ErrorLevel
        MsgBox, Error: Unable to run Python. Please check your Python installation.
}

; Function to install a Python package using pip
InstallPythonPackage(package) {
    RunWait, %pipPath% install %package%,, Hide
    if ErrorLevel
        MsgBox, Error: Unable to install package %package%. Please check your pip installation.
    else
        MsgBox, Package %package% installed successfully.
}

; Function to update all Python packages
UpdateAllPythonPackages() {
    RunWait, %pipPath% list --outdated --format=freeze | %pipPath% install -U,, Hide
    if ErrorLevel
        MsgBox, Error: Unable to update packages. Please check your pip installation.
    else
        MsgBox, All packages updated successfully.
}

; Function to create a new Python virtual environment
CreateVirtualEnvironment(envName) {
    RunWait, %pythonPath% -m venv %envName%,, Hide
    if ErrorLevel
        MsgBox, Error: Unable to create virtual environment %envName%.
    else
        MsgBox, Virtual environment %envName% created successfully.
}

; Function to activate a Python virtual environment
ActivateVirtualEnvironment(envName) {
    EnvPath := A_WorkingDir . "\" . envName . "\Scripts\activate.bat"
    if FileExist(EnvPath) {
        Run, %ComSpec% /k "%EnvPath%"
    } else {
        MsgBox, Error: Virtual environment %envName% not found.
    }
}

; Hotkey to check Python version
^!v::
    CheckPythonVersion()
return

; Hotkey to install a Python package
^!i::
    InputBox, package, Install Python Package, Enter the name of the package to install:
    if !ErrorLevel
        InstallPythonPackage(package)
return

; Hotkey to update all Python packages
^!u::
    UpdateAllPythonPackages()
return

; Hotkey to create a new Python virtual environment
^!n::
    InputBox, envName, Create Virtual Environment, Enter the name for the new virtual environment:
    if !ErrorLevel
        CreateVirtualEnvironment(envName)
return

; Hotkey to activate a Python virtual environment
^!e::
    InputBox, envName, Activate Virtual Environment, Enter the name of the virtual environment to activate:
    if !ErrorLevel
        ActivateVirtualEnvironment(envName)
return

; Additional Python-related hotkeys and functions can be added here as needed

; End of Python 3 Macros script
