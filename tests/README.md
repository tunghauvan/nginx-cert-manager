# NGINX Certificate Manager Tests

This directory contains tests for the NGINX Certificate Manager project.

## Running Tests

### Using the run_tests.py Script

The easiest way to run tests is to use the included `run_tests.py` script:

```bash
# Run all tests
python run_tests.py

# Run with verbose output
python run_tests.py -v

# Run a specific test file
python run_tests.py -p tests/test_http_agent.py

# Run all tests in a specific directory
python run_tests.py -p tests/unit
```

### Using unittest Directly

You can also run tests using Python's unittest module:

```bash
# Run all tests
python -m unittest discover tests

# Run a specific test file
python -m unittest tests/test_http_agent.py

# Run a specific test class
python -m unittest tests.test_http_agent.TestHTTPAgentAPI

# Run a specific test method
python -m unittest tests.test_http_agent.TestHTTPAgentAPI.test_health_check
```

### Using pytest (if installed)

If you prefer pytest, you can use:

```bash
# Install pytest if not already installed
pip install pytest

# Run all tests
pytest tests/

# Run with verbose output
pytest -v tests/

# Run a specific test file
pytest tests/test_http_agent.py
```

## Environment Setup for Tests

Tests may use mock dependencies or require specific environment variables. The `run_tests.py` script automatically sets up the appropriate testing environment.

If running tests directly with unittest or pytest, you may need to set:

```bash
# Set this environment variable to enable test mocks
export TESTING=true  # (Linux/Mac)
set TESTING=true     # (Windows)
```

## Writing New Tests

When adding new functionality, please add corresponding tests. Tests should:

1. Be placed in the `tests/` directory
2. Follow the naming convention `test_*.py`
3. Use Python's unittest framework or pytest
4. Mock external dependencies when appropriate

For examples, see the existing test files like `tests/test_http_agent.py` or `tests/test_entrypoint.py`.
