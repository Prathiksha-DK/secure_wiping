import requests
import json
import time

# API endpoints
BOOM_WIPE_URL = "http://localhost:5695"
PENDRIVE_WIPE_URL = "http://localhost:8743"

def test_boom_wipe_service():
    """Test the main Boom Wipe service"""
    print("=" * 60)
    print("TESTING MAIN BOOM WIPE SERVICE (Port 5695)")
    print("=" * 60)
    
    try:
        # Test health check
        print("\n1. Testing health check...")
        response = requests.get(f"{BOOM_WIPE_URL}/health")
        print(f"Health Status: {response.status_code}")
        print(f"Response: {response.json()}")
        
        # Test device listing
        print("\n2. Testing device listing...")
        response = requests.get(f"{BOOM_WIPE_URL}/devices")
        if response.status_code == 200:
            devices = response.json()['devices']
            print(f"Found {len(devices)} devices:")
            for i, device in enumerate(devices, 1):
                print(f"  {i}. {device['name']} ({device['size_gb']} GB)")
        else:
            print(f"Error: {response.json()}")
        
        # Test active wipes
        print("\n3. Testing active wipes...")
        response = requests.get(f"{BOOM_WIPE_URL}/active-wipes")
        print(f"Active wipes: {response.json()}")
        
        # Example boom wipe (COMMENTED OUT FOR SAFETY)
        print("\n4. Example Boom Wipe request (DEMO - NOT EXECUTED):")
        example_request = {
            "device": "Primary SSD (512GB)"
        }
        print(f"POST {BOOM_WIPE_URL}/boom-wipe")
        print(f"Body: {json.dumps(example_request, indent=2)}")
        print("*** THIS IS JUST AN EXAMPLE - NOT EXECUTED FOR SAFETY ***")
        
    except requests.exceptions.ConnectionError:
        print("ERROR: Could not connect to Boom Wipe service. Make sure it's running on port 5695.")
    except Exception as e:
        print(f"ERROR: {e}")

def test_pendrive_wipe_service():
    """Test the Pendrive Wipe service"""
    print("\n" + "=" * 60)
    print("TESTING PENDRIVE WIPE SERVICE (Port 8743)")
    print("=" * 60)
    
    try:
        # Test health check
        print("\n1. Testing health check...")
        response = requests.get(f"{PENDRIVE_WIPE_URL}/health")
        print(f"Health Status: {response.status_code}")
        print(f"Response: {response.json()}")
        
        # Test pendrive listing
        print("\n2. Testing pendrive listing...")
        response = requests.get(f"{PENDRIVE_WIPE_URL}/pendrives")
        if response.status_code == 200:
            pendrives = response.json()['pendrives']
            print(f"Found {len(pendrives)} removable devices:")
            for i, pendrive in enumerate(pendrives, 1):
                print(f"  {i}. {pendrive['name']}")
        else:
            print(f"Error: {response.json()}")
        
        # Test active wipes
        print("\n3. Testing active wipes...")
        response = requests.get(f"{PENDRIVE_WIPE_URL}/active-wipes")
        print(f"Active wipes: {response.json()}")
        
        # Example pendrive wipe (COMMENTED OUT FOR SAFETY)
        print("\n4. Example Pendrive Wipe requests (DEMO - NOT EXECUTED):")
        
        example_request = {
            "device": "E (16GB) - FAT32"
        }
        print(f"\n   a) Full Pendrive Wipe:")
        print(f"   POST {PENDRIVE_WIPE_URL}/wipe-pendrive")
        print(f"   Body: {json.dumps(example_request, indent=6)}")
        
        print(f"\n   b) Quick Wipe:")
        print(f"   POST {PENDRIVE_WIPE_URL}/quick-wipe")
        print(f"   Body: {json.dumps(example_request, indent=6)}")
        
        print("\n*** THESE ARE JUST EXAMPLES - NOT EXECUTED FOR SAFETY ***")
        
    except requests.exceptions.ConnectionError:
        print("ERROR: Could not connect to Pendrive Wipe service. Make sure it's running on port 8743.")
    except Exception as e:
        print(f"ERROR: {e}")

def print_api_documentation():
    """Print API documentation"""
    print("\n" + "=" * 60)
    print("API DOCUMENTATION")
    print("=" * 60)
    
    print("\n📡 MAIN BOOM WIPE SERVICE (Port 5695)")
    print("────────────────────────────────────────")
    print("• POST /boom-wipe          - Execute boom wipe on device")
    print("• GET  /devices            - List all storage devices") 
    print("• GET  /active-wipes       - List active wipe operations")
    print("• GET  /wipe-status/<id>   - Get status of specific wipe")
    print("• GET  /health             - Health check")
    
    print("\n💾 PENDRIVE WIPE SERVICE (Port 8743)")
    print("────────────────────────────────────────")
    print("• POST /wipe-pendrive      - Execute boom wipe on pendrive")
    print("• POST /quick-wipe         - Execute quick wipe (1 pass)")
    print("• GET  /pendrives          - List removable devices")
    print("• GET  /active-wipes       - List active wipe operations")
    print("• GET  /wipe-status/<id>   - Get status of specific wipe") 
    print("• GET  /health             - Health check")
    
    print("\n🔧 BOOM WIPE METHOD EXPLANATION")
    print("────────────────────────────────────────")
    print("The Boom Wipe method works by:")
    print("1. Calculating optimal 'bomb' positions across the storage device")
    print("2. Each bomb covers a specific memory sector (1MB for HDDs, 512KB for pendrives)")
    print("3. Multiple bombs are placed in parallel using multi-threading")
    print("4. Each bomb performs 3 overwrite passes with different patterns:")
    print("   - Pass 1: All zeros (0x00)")
    print("   - Pass 2: All ones (0xFF)")  
    print("   - Pass 3: Random data")
    print("5. All operations use direct device I/O with no buffering")
    print("6. Progress is tracked in real-time")
    
    print("\n⚠️  SAFETY WARNINGS")
    print("────────────────────────────────────────")
    print("• These operations will PERMANENTLY destroy all data")
    print("• Always run as Administrator for device access")
    print("• Verify device names carefully before wiping")
    print("• Operations cannot be undone once started")
    print("• Test on non-important devices first")

if __name__ == "__main__":
    print("BOOM WIPE SERVICE TESTER")
    print("=" * 60)
    print("This script tests the Boom Wipe APIs without executing destructive operations")
    print("Make sure both services are running before testing!")
    
    # Test both services
    test_boom_wipe_service()
    test_pendrive_wipe_service()
    
    # Show API documentation
    print_api_documentation()
    
    print("\n" + "=" * 60)
    print("TESTING COMPLETE")
    print("=" * 60)
