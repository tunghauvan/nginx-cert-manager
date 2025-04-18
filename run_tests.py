#!/usr/bin/env python3
"""
Test runner for the NGINX Certificate Manager project.
This script discovers and runs all tests in the tests directory.
"""

import os
import sys
import unittest
import argparse

def run_tests(test_path=None, verbose=False):
    """
    Run tests from the specified path.
    
    Args:
        test_path: Path to specific test file or directory
        verbose: Whether to show detailed output
    """
    # Set testing environment variable to enable mocks
    os.environ['TESTING'] = 'true'
    
    # Discover and run tests
    loader = unittest.TestLoader()
    
    if test_path:
        if os.path.isfile(test_path):
            # Run specific test file
            test_dir = os.path.dirname(test_path)
            test_file = os.path.basename(test_path)
            suite = loader.discover(test_dir, pattern=test_file)
        else:
            # Run all tests in specific directory
            suite = loader.discover(test_path)
    else:
        # Run all tests in the tests directory
        suite = loader.discover('tests')
    
    # Configure verbosity
    verbosity = 2 if verbose else 1
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    
    # Return exit code based on test success
    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run tests for NGINX Certificate Manager')
    parser.add_argument('--path', '-p', help='Path to specific test file or directory')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed output')
    
    args = parser.parse_args()
    
    sys.exit(run_tests(args.path, args.verbose))
