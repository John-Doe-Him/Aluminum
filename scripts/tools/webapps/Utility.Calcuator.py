
import math
import re
from typing import Union, List, Dict, Any

class WebCalculator:
    """
    A comprehensive web calculator utility for the Aluminum web browser.
    This class provides a wide range of mathematical operations and functions
    to support complex calculations within the browser environment.
    """

    def __init__(self):
        """
        Initialize the WebCalculator with default settings and constants.
        """
        self.memory: float = 0
        self.history: List[str] = []
        self.constants: Dict[str, float] = {
            'pi': math.pi,
            'e': math.e,
            'phi': (1 + math.sqrt(5)) / 2,  # Golden ratio
            'c': 299792458,  # Speed of light in m/s
            'g': 9.80665,  # Acceleration due to gravity in m/s^2
        }

    def evaluate(self, expression: str) -> Union[float, str]:
        """
        Evaluate a mathematical expression and return the result.

        Args:
            expression (str): The mathematical expression to evaluate.

        Returns:
            Union[float, str]: The result of the evaluation or an error message.
        """
        try:
            # Replace constants with their values
            for const, value in self.constants.items():
                expression = expression.replace(const, str(value))

            # Safely evaluate the expression
            result = self._safe_eval(expression)
            self.history.append(f"{expression} = {result}")
            return result
        except Exception as e:
            return f"Error: {str(e)}"

    def _safe_eval(self, expression: str) -> float:
        """
        Safely evaluate a mathematical expression using a custom parser.

        Args:
            expression (str): The expression to evaluate.

        Returns:
            float: The result of the evaluation.

        Raises:
            ValueError: If the expression contains invalid characters or operations.
        """
        # Remove whitespace and convert to lowercase
        expression = expression.replace(' ', '').lower()

        # Check for invalid characters
        if re.search(r'[^0-9+\-*/^().a-z]', expression):
            raise ValueError("Invalid characters in expression")

        # Tokenize the expression
        tokens = re.findall(r'(\d+\.?\d*|\+|\-|\*|/|\^|\(|\)|[a-z]+)', expression)

        # Convert infix notation to Reverse Polish Notation (RPN)
        rpn = self._infix_to_rpn(tokens)

        # Evaluate RPN
        return self._evaluate_rpn(rpn)

    def _infix_to_rpn(self, tokens: List[str]) -> List[str]:
        """
        Convert infix notation to Reverse Polish Notation (RPN).

        Args:
            tokens (List[str]): List of tokens in infix notation.

        Returns:
            List[str]: Tokens in RPN.
        """
        precedence = {'+': 1, '-': 1, '*': 2, '/': 2, '^': 3}
        output = []
        operators = []

        for token in tokens:
            if token.replace('.', '').isdigit():
                output.append(token)
            elif token in self._get_supported_functions():
                operators.append(token)
            elif token == '(':
                operators.append(token)
            elif token == ')':
                while operators and operators[-1] != '(':
                    output.append(operators.pop())
                operators.pop()  # Remove the '('
            elif token in precedence:
                while (operators and operators[-1] != '(' and
                       precedence.get(operators[-1], 0) >= precedence[token]):
                    output.append(operators.pop())
                operators.append(token)

        while operators:
            output.append(operators.pop())

        return output

    def _evaluate_rpn(self, rpn: List[str]) -> float:
        """
        Evaluate an expression in Reverse Polish Notation (RPN).

        Args:
            rpn (List[str]): Tokens in RPN.

        Returns:
            float: The result of the evaluation.

        Raises:
            ValueError: If the expression is invalid or contains unsupported operations.
        """
        stack = []

        for token in rpn:
            if token.replace('.', '').isdigit():
                stack.append(float(token))
            elif token in self._get_supported_functions():
                args = self._get_function_args(token, stack)
                result = self._apply_function(token, args)
                stack.append(result)
            elif token in {'+', '-', '*', '/', '^'}:
                b, a = stack.pop(), stack.pop()
                if token == '+':
                    stack.append(a + b)
                elif token == '-':
                    stack.append(a - b)
                elif token == '*':
                    stack.append(a * b)
                elif token == '/':
                    if b == 0:
                        raise ValueError("Division by zero")
                    stack.append(a / b)
                elif token == '^':
                    stack.append(a ** b)

        if len(stack) != 1:
            raise ValueError("Invalid expression")

        return stack[0]

    def _get_supported_functions(self) -> List[str]:
        """
        Get a list of supported mathematical functions.

        Returns:
            List[str]: List of supported function names.
        """
        return [
            'sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'sinh', 'cosh', 'tanh',
            'log', 'log10', 'exp', 'sqrt', 'abs', 'ceil', 'floor', 'round',
            'factorial', 'degrees', 'radians'
        ]

    def _get_function_args(self, func: str, stack: List[float]) -> List[float]:
        """
        Get the required number of arguments for a given function.

        Args:
            func (str): The function name.
            stack (List[float]): The current evaluation stack.

        Returns:
            List[float]: List of arguments for the function.

        Raises:
            ValueError: If there are not enough arguments on the stack.
        """
        args_count = 1
        if func in {'log'}:
            args_count = 2

        if len(stack) < args_count:
            raise ValueError(f"Not enough arguments for {func}")

        return [stack.pop() for _ in range(args_count)][::-1]

    def _apply_function(self, func: str, args: List[float]) -> float:
        """
        Apply a mathematical function to the given arguments.

        Args:
            func (str): The function name.
            args (List[float]): List of arguments for the function.

        Returns:
            float: The result of applying the function.

        Raises:
            ValueError: If the function is not supported or the arguments are invalid.
        """
        try:
            if func == 'sin':
                return math.sin(args[0])
            elif func == 'cos':
                return math.cos(args[0])
            elif func == 'tan':
                return math.tan(args[0])
            elif func == 'asin':
                return math.asin(args[0])
            elif func == 'acos':
                return math.acos(args[0])
            elif func == 'atan':
                return math.atan(args[0])
            elif func == 'sinh':
                return math.sinh(args[0])
            elif func == 'cosh':
                return math.cosh(args[0])
            elif func == 'tanh':
                return math.tanh(args[0])
            elif func == 'log':
                return math.log(args[1], args[0])
            elif func == 'log10':
                return math.log10(args[0])
            elif func == 'exp':
                return math.exp(args[0])
            elif func == 'sqrt':
                return math.sqrt(args[0])
            elif func == 'abs':
                return abs(args[0])
            elif func == 'ceil':
                return math.ceil(args[0])
            elif func == 'floor':
                return math.floor(args[0])
            elif func == 'round':
                return round(args[0])
            elif func == 'factorial':
                return math.factorial(int(args[0]))
            elif func == 'degrees':
                return math.degrees(args[0])
            elif func == 'radians':
                return math.radians(args[0])
            else:
                raise ValueError(f"Unsupported function: {func}")
        except Exception as e:
            raise ValueError(f"Error in function {func}: {str(e)}")

    def store_in_memory(self, value: float) -> None:
        """
        Store a value in the calculator's memory.

        Args:
            value (float): The value to store in memory.
        """
        self.memory = value

    def recall_from_memory(self) -> float:
        """
        Recall the value stored in the calculator's memory.

        Returns:
            float: The value stored in memory.
        """
        return self.memory

    def clear_memory(self) -> None:
        """
        Clear the calculator's memory.
        """
        self.memory = 0

    def get_history(self) -> List[str]:
        """
        Get the calculation history.

        Returns:
            List[str]: A list of previous calculations and their results.
        """
        return self.history

    def clear_history(self) -> None:
        """
        Clear the calculation history.
        """
        self.history = []

    def add_custom_constant(self, name: str, value: float) -> None:
        """
        Add a custom constant to the calculator.

        Args:
            name (str): The name of the constant.
            value (float): The value of the constant.

        Raises:
            ValueError: If the constant name is invalid or already exists.
        """
        if not name.isalpha():
            raise ValueError("Constant name must contain only alphabetic characters")
        if name in self.constants:
            raise ValueError(f"Constant '{name}' already exists")
        self.constants[name] = value

    def remove_custom_constant(self, name: str) -> None:
        """
        Remove a custom constant from the calculator.

        Args:
            name (str): The name of the constant to remove.

        Raises:
            ValueError: If the constant does not exist or is a built-in constant.
        """
        if name not in self.constants:
            raise ValueError(f"Constant '{name}' does not exist")
        if name in {'pi', 'e', 'phi', 'c', 'g'}:
            raise ValueError(f"Cannot remove built-in constant '{name}'")
        del self.constants[name]

    def get_constants(self) -> Dict[str, float]:
        """
        Get all available constants.

        Returns:
            Dict[str, float]: A dictionary of constant names and their values.
        """
        return self.constants

    def convert_units(self, value: float, from_unit: str, to_unit: str) -> float:
        """
        Convert a value from one unit to another.

        Args:
            value (float): The value to convert.
            from_unit (str): The unit to convert from.
            to_unit (str): The unit to convert to.

        Returns:
            float: The converted value.

        Raises:
            ValueError: If the units are not supported or incompatible.
        """
        # Define conversion factors
        length_units = {
            'm': 1, 'km': 1000, 'cm': 0.01, 'mm': 0.001, 'in': 0.0254,
            'ft': 0.3048, 'yd': 0.9144, 'mi': 1609.344
        }
        weight_units = {
            'kg': 1, 'g': 0.001, 'mg': 1e-6, 'lb': 0.45359237, 'oz': 0.028349523125
        }
        volume_units = {
            'l': 1, 'ml': 0.001, 'gal': 3.78541, 'qt': 0.946353, 'pt': 0.473176,
            'cup': 0.236588, 'floz': 0.0295735
        }

        # Determine the category of units
        if from_unit in length_units and to_unit in length_units:
            category = length_units
        elif from_unit in weight_units and to_unit in weight_units:
            category = weight_units
        elif from_unit in volume_units and to_unit in volume_units:
            category = volume_units
        else:
            raise ValueError("Unsupported or incompatible units")

        # Perform the conversion
        base_value = value * category[from_unit]
        converted_value = base_value / category[to_unit]

        return converted_value

    def calculate_percentage(self, value: float, percentage: float) -> Dict[str, float]:
        """
        Calculate percentage-related values.

        Args:
            value (float): The base value.
            percentage (float): The percentage to calculate.

        Returns:
            Dict[str, float]: A dictionary containing various percentage calculations.
        """
        result = {
            'percentage_amount': (value * percentage) / 100,
            'total_with_percentage': value + (value * percentage) / 100,
            'total_less_percentage': value - (value * percentage) / 100,
            'is_what_percent_of': (percentage / value) * 100 if value != 0 else None
        }
        return result

    def solve_quadratic_equation(self, a: float, b: float, c: float) -> Dict[str, Any]:
        """
        Solve a quadratic equation of the form ax^2 + bx + c = 0.

        Args:
            a (float): Coefficient of x^2.
            b (float): Coefficient of x.
            c (float): Constant term.

        Returns:
            Dict[str, Any]: A dictionary containing the solutions and related information.
        """
        discriminant = b**2 - 4*a*c
        result = {
            'discriminant': discriminant,
            'nature': 'Real and distinct' if discriminant > 0 else 'Real and equal' if discriminant == 0 else 'Complex',
            'solutions': []
        }

        if discriminant >= 0:
            x1 = (-b + math.sqrt(discriminant)) / (2*a)
            x2 = (-b - math.sqrt(discriminant)) / (2*a)
            result['solutions'] = [x1, x2]
        else:
            real_part = -b / (2*a)
            imag_part = math.sqrt(abs(discriminant)) / (2*a)
            result['solutions'] = [
                complex(real_part, imag_part),
                complex(real_part, -imag_part)
            ]

        return result

    def calculate_statistics(self, data: List[float]) -> Dict[str, float]:
        """
        Calculate various statistical measures for a given dataset.

        Args:
            data (List[float]): A list of numerical values.

        Returns:
            Dict[str, float]: A dictionary containing various statistical measures.
        """
        n = len(data)
        if n == 0:
            return {
                'count': 0,
                'sum': 0,
                'mean': None,
                'median': None,
                'mode': None,
                'range': None,
                'variance': None,
                'std_dev': None
            }

        sorted_data = sorted(data)
        sum_data = sum(data)
        mean = sum
