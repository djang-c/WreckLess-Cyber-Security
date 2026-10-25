"""Code validation for custom components.

Adapted from langflow-ai/langflow (MIT), src/backend/base/langflow/utils/validate.py at
8f4515e6 (parent of the CVE-2025-3248 fix, PR 6911): logging and pydantic removed, the logic of
``validate_code`` kept as is. To find out whether a function definition is valid it *executes* the
definition, and executing a ``def`` evaluates its decorators and default arguments.
"""
import ast
import importlib
import logging

log = logging.getLogger(__name__)


def validate_code(code):
    # Initialize the errors dictionary
    errors = {"imports": {"errors": []}, "function": {"errors": []}}

    # Parse the code string into an abstract syntax tree (AST)
    try:
        tree = ast.parse(code)
    except Exception as e:  # noqa: BLE001
        log.debug("Error parsing code", exc_info=True)
        errors["function"]["errors"].append(str(e))
        return errors

    tree.type_ignores = []

    # Evaluate the import statements
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                try:
                    importlib.import_module(alias.name)
                except ModuleNotFoundError as e:
                    errors["imports"]["errors"].append(str(e))

    # Evaluate the function definition
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            code_obj = compile(ast.Module(body=[node], type_ignores=[]), "<string>", "exec")
            try:
                exec(code_obj)
            except Exception as e:  # noqa: BLE001
                log.debug("Error executing function code", exc_info=True)
                errors["function"]["errors"].append(str(e))

    # Return the errors dictionary
    return errors
