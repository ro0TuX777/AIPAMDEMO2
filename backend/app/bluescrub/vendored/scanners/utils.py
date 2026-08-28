"""
Shared utilities for BlueScrub scanners.
"""

import subprocess


import logging

logger = logging.getLogger(__name__)
def run_command(cmd, timeout=60):
    """Run a command and return the result with optimized timeout"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ss: %s...", timeout, cmd[:100])
        return {'success': False, 'error': f'Command timed out after {timeout} seconds'}
    except Exception as e:
        logger.warning("Command failed: %s", e)
        return {'success': False, 'error': str(e)}

