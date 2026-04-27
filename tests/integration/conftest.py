"""Pytest configuration for integration tests."""

import sys
import os

# Add project root to path
project_root = os.path.join(os.path.dirname(__file__), "../../")
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Add services/gateway to path for main.py imports
gateway_path = os.path.join(project_root, "services/gateway")
if gateway_path not in sys.path:
    sys.path.insert(0, gateway_path)
