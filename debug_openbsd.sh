#!/usr/bin/env python3
"""
OpenBSD PyBitmessage Network Debug Script
Findet heraus warum keine echten Peers gefunden werden
"""

import socket
import sys
import logging
import dns.resolver  # pip install dnspython

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('debug')

def test_dns_resolution():
    """Testet ob DNS für Bitmessage funktioniert"""
    print("=== DNS Resolution Test ===")
    
    hosts = [
        "bitmessage.org",
        "strap4.bitmessage.org", 
        "bootstrap8444.bitmessage.org"
    ]
    
    for host in hosts:
        try:
            # Methode 1: Standard socket
            ip = socket.gethostbyname(host)
            print(f"✅ socket.gethostbyname('{host}') -> {ip}")
        except Exception as e:
            print(f"❌ socket.gethostbyname('{host}') failed: {e}")
        
        try:
            # Methode 2: getaddrinfo (moderner)
            addrinfo = socket.getaddrinfo(host, 8444)
            ips = [addr[4][0] for addr in addrinfo]
            print(f"✅ socket.getaddrinfo('{host}') -> {ips}")
        except Exception as e:
            print(f"❌ socket.getaddrinfo('{host}') failed: {e}")
        
        try:
            # Methode 3: dnspython (falls installiert)
            answers = dns.resolver.resolve(host, 'A')
            ips = [str(rdata) for rdata in answers]
            print(f"✅ dnspython('{host}') -> {ips}")
        except Exception as e:
            print(f"❌ dnspython('{host}') failed: {e}")

def test_socket_creation():
    """Testet Socket-Erstellung auf OpenBSD"""
    print("\n=== Socket Creation Test ===")
    
    try:
        # IPv4 Socket
        sock4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock4.setblocking(False)
        print("✅ IPv4 Socket creation: SUCCESS")
        sock4.close()
    except Exception as e:
        print(f"❌ IPv4 Socket creation: {e}")
    
    try:
        # IPv6 Socket
        sock6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock6.setblocking(False)
        print("✅ IPv6 Socket creation: SUCCESS")
        sock6.close()
    except Exception as e:
        print(f"❌ IPv6 Socket creation: {e}")

def test_network_connectivity():
    """Testet Netzwerk-Connectivity zu bekannten Peers"""
    print("\n=== Network Connectivity Test ===")
    
    known_peers = [
        ("195.122.229.174", 8444),
        ("77.239.124.29", 8444),
        ("85.214.78.238", 8444)  # bitmessage.org
    ]
    
    for ip, port in known_peers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                print(f"✅ Connect to {ip}:{port}: SUCCESS")
            else:
                print(f"❌ Connect to {ip}:{port}: FAILED (error {result})")
        except Exception as e:
            print(f"❌ Connect to {ip}:{port}: EXCEPTION {e}")

def test_broadcast_behavior():
    """Testet Broadcast-Verhalten auf OpenBSD"""
    print("\n=== Broadcast Behavior Test ===")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        print("✅ Broadcast socket configuration: SUCCESS")
        
        # Test broadcast
        test_data = b"BITMESSAGE_TEST"
        sock.sendto(test_data, ('255.255.255.255', 8444))
        print("✅ Broadcast send: SUCCESS")
        sock.close()
    except Exception as e:
        print(f"❌ Broadcast test: {e}")

def check_pybitmessage_bootstrap():
    """Simuliert PyBitmessage's Bootstrap Process"""
    print("\n=== PyBitmessage Bootstrap Simulation ===")
    
    # Simuliere was PyBitmessage tut um Peers zu finden
    try:
        import urllib.request
        import json
        
        # Versuche bootstrap8444.bitmessage.org zu kontaktieren
        url = "http://bootstrap8444.bitmessage.org:80/"
        response = urllib.request.urlopen(url, timeout=10)
        print("✅ Bootstrap HTTP request: SUCCESS")
    except Exception as e:
        print(f"❌ Bootstrap HTTP request: {e}")

if __name__ == "__main__":
    print(f"Python {sys.version} on {sys.platform}")
    print("=" * 50)
    
    test_dns_resolution()
    test_socket_creation() 
    test_network_connectivity()
    test_broadcast_behavior()
    check_pybitmessage_bootstrap()
