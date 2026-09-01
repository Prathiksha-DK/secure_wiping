#!/usr/bin/env python3
"""
Test script for device API endpoint
"""
import requests
import json

def test_device_api():
    """Test the device API endpoint"""
    try:
        url = "http://192.168.137.191:8586/api/devices"
        print(f"🔍 Testing device API: {url}")
        
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Device API endpoint working!")
            print(f"📱 Found {data.get('count', 0)} devices:")
            
            for i, device in enumerate(data.get('devices', []), 1):
                print(f"  {i}. {device.get('name', 'Unknown')}")
                print(f"     Type: {device.get('type', 'Unknown')}")
                print(f"     Size: {device.get('size', 'Unknown')}")
                print(f"     Health: {device.get('health', 'Unknown')}")
                print()
        else:
            print(f"❌ API returned status code: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to connect to API: {e}")

if __name__ == "__main__":
    test_device_api()
