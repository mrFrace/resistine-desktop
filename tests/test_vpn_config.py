#!/usr/bin/env python3
"""
Test script to create a VPN configuration manually for testing
"""
import os
import sys
sys.path.append('.')

from plugins.vpn.wireguard.vpn_functions_windows import get_writable_wireguard_dir

def create_test_vpn_config():
    """Create a test VPN configuration"""
    
    # Get the config directory
    config_dir = get_writable_wireguard_dir()  
    config_path = os.path.join(config_dir, "resistine.conf")
    
    # Create a basic WireGuard configuration for testing
    # Note: These are example values - replace with real ones from your VPN provider
    test_config = """
"""

    # Create directory if it doesn't exist
    os.makedirs(config_dir, exist_ok=True)
    
    # Write the config file
    with open(config_path, 'w', encoding='utf-8') as f:
        f.write(test_config)
    
    print(f"Test VPN config created at: {config_path}")
    print("Contents:")
    print(test_config)
    
    return config_path

if __name__ == "__main__":
    create_test_vpn_config()