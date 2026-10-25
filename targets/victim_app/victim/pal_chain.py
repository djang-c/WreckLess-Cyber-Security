"""Replica of langchain_experimental.pal_chain.base @ aebdb1a (CVE-2023-44467).

Validation logic is copied from upstream (MIT, LangChain). The denylist misses
``__import__``, so generated "math" code can import os and run anything.
"""
from __future__ import annotations

import ast
from typing import Optional

COMMAND_EXECUTION_FUNCTIONS = ["system", "exec", "execfile", "eval"]


class PALValidation:
    SOLUTION_EXPRESSION_TYPE_FUNCTION = ast.FunctionDef
    SOLUTION_EXPRESSION_TYPE_VARIABLE = ast.Name

    def __init__(
        self,
        solution_expression_name: Optional[str] = None,
        solution_expression_type: Optional[type] = None,
        allow_imports: bool = False,
        allow_command_exec: bool = False,
    ):
        self.solution_expression_name = solution_expression_name
        self.solution_expression_type = solution_expression_type
        self.allow_imports = allow_imports
        self.allow_command_exec = allow_command_exec


MATH_VALIDATION = PALValidation(
    solution_expression_name="solution",
    solution_expression_type=PALValidation.SOLUTION_EXPRESSION_TYPE_FUNCTION,
)


def validate_code(code: str, code_validations: PALValidation) -> None:
    try:
        code_tree = ast.parse(code)
    except (SyntaxError, UnicodeDecodeError):
        raise ValueError(f"Generated code is not valid python code: {code}")

    found_solution_expr = code_validations.solution_expression_name is None
    has_imports = False
    for node in ast.iter_child_nodes(code_tree):
        if (
            code_validations.solution_expression_name is not None
            and isinstance(node, code_validations.solution_expression_type)
            and getattr(node, "name", None) == code_validations.solution_expression_name
        ):
            found_solution_expr = True
        if isinstance(node, ast.Assign):
            for target_node in node.targets:
                if (
                    isinstance(target_node, ast.Name)
                    and target_node.id == code_validations.solution_expression_name
                ):
                    found_solution_expr = True
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            has_imports = True
    if not found_solution_expr:
        raise ValueError("Generated code is missing the solution expression")
    if not code_validations.allow_imports and has_imports:
        raise ValueError(f"Generated code has disallowed imports: {code}")
    if not code_validations.allow_command_exec or not code_validations.allow_imports:
        for node in ast.walk(code_tree):
            if (
                (not code_validations.allow_command_exec)
                and isinstance(node, ast.Call)
                and (
                    (hasattr(node.func, "id") and node.func.id in COMMAND_EXECUTION_FUNCTIONS)
                    or (isinstance(node.func, ast.Attribute)
                        and node.func.attr in COMMAND_EXECUTION_FUNCTIONS)
                )
            ):
                raise ValueError(f"Found illegal command execution function in code {code}")
            if (not code_validations.allow_imports) and isinstance(node, (ast.Import, ast.ImportFrom)):
                raise ValueError(f"Generated code has disallowed imports: {code}")


def run_pal(code: str, code_validations: PALValidation = MATH_VALIDATION):
    """What PALChain._call does after the LLM returns code: validate, then exec."""
    validate_code(code, code_validations)
    scope: dict = {}
    exec(code, scope)
    return scope["solution"]()
