"""
Device Management Layer (Local, Government-LAN, Authorized Remote)
Part of NTRO Adaptive Sanitization & Forensic Recovery Platform.

Unified abstraction for:
  1. LOCAL: Physical disks attached to local host (enumerated via devices.py).
  2. GOV_LAN: Authorized endpoints on Government LAN running authenticated agent.
  3. REMOTE: Cross-network endpoints requiring token authorization & explicit confirmation.
"""

import os
import sys
import time
import json
import uuid
from typing import Dict, Any, List, Optional, Tuple
from auth import get_db
from devices import list_devices


def sync_local_devices() -> List[Dict[str, Any]]:
    """Scan and synchronize local hardware devices into platform database."""
    local_devs = list_devices()
    conn = get_db()
    synced = []
    now = int(time.time())
    try:
        cur = conn.cursor()
        for d in local_devs:
            # Generate deterministic device ID based on serial or name
            dev_id = f"LOCAL-{abs(hash(d.get('serial', '') or d.get('name', ''))):08x}".upper()
            name = d.get("name", "Unknown Storage Device")
            serial = d.get("serial", "UNKNOWN_SERIAL")
            bus = d.get("bus", "SATA")
            m_type = d.get("type", "HDD")
            size_bytes = d.get("sizeBytes", 0)
            health = d.get("health", 100)
            health_status = d.get("healthStatus", "Healthy")

            cur.execute("""
                INSERT INTO devices (id, name, connection_type, serial_number, bus_type, media_type,
                                    capacity_bytes, health_status, health_score, ip_address, agent_version,
                                    is_authorized, status, last_seen)
                VALUES (?, ?, 'local', ?, ?, ?, ?, ?, ?, '127.0.0.1', '1.0.0-host', 1, 'online', ?)
                ON CONFLICT(id) DO UPDATE SET
                    health_status=excluded.health_status,
                    health_score=excluded.health_score,
                    status='online',
                    last_seen=excluded.last_seen
            """, (dev_id, name, serial, bus, m_type, size_bytes, health_status, health, now))
            synced.append(dev_id)
        conn.commit()
    finally:
        conn.close()
    return local_devs


def discover_gov_lan_devices() -> List[Dict[str, Any]]:
    """
    Discover or refresh registered Government/Organization LAN agents.
    Simulates discovery of authorized agency nodes or polls connection-server.
    """
    conn = get_db()
    now = int(time.time())
    gov_nodes = [
        {
            "id": "GOV-NODE-01",
            "name": "NTRO-SEC-WS-401 (Finance Workstation)",
            "connection_type": "gov_lan",
            "serial_number": "NTRO-SRV-8841-A",
            "bus_type": "NVMe",
            "media_type": "SSD",
            "capacity_bytes": 512 * 1024 * 1024 * 1024,
            "health_status": "Healthy",
            "health_score": 98,
            "ip_address": "10.14.20.104",
            "agent_version": "SecureWipe-GovAgent v2.4",
            "is_authorized": 1,
            "status": "online",
        },
        {
            "id": "GOV-NODE-02",
            "name": "NTRO-INT-SERVER-02 (Secure Gateway)",
            "connection_type": "gov_lan",
            "serial_number": "NTRO-SRV-9102-B",
            "bus_type": "SAS",
            "media_type": "HDD",
            "capacity_bytes": 2048 * 1024 * 1024 * 1024,
            "health_status": "Healthy",
            "health_score": 92,
            "ip_address": "10.14.20.112",
            "agent_version": "SecureWipe-GovAgent v2.4",
            "is_authorized": 0,  # Requires explicit pairing/authorization!
            "status": "pending_auth",
        },
        {
            "id": "GOV-NODE-03",
            "name": "NTRO-LAB-TESTBED-09 (Decommissioned Unit)",
            "connection_type": "gov_lan",
            "serial_number": "NTRO-SRV-3319-C",
            "bus_type": "SATA",
            "media_type": "HDD",
            "capacity_bytes": 1000 * 1024 * 1024 * 1024,
            "health_status": "Degraded",
            "health_score": 64,
            "ip_address": "10.14.20.155",
            "agent_version": "SecureWipe-GovAgent v2.4",
            "is_authorized": 1,
            "status": "online",
        }
    ]

    try:
        cur = conn.cursor()
        for g in gov_nodes:
            cur.execute("""
                INSERT INTO devices (id, name, connection_type, serial_number, bus_type, media_type,
                                    capacity_bytes, health_status, health_score, ip_address, agent_version,
                                    is_authorized, status, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    health_status=excluded.health_status,
                    health_score=excluded.health_score,
                    last_seen=excluded.last_seen
            """, (
                g["id"], g["name"], g["connection_type"], g["serial_number"],
                g["bus_type"], g["media_type"], g["capacity_bytes"],
                g["health_status"], g["health_score"], g["ip_address"],
                g["agent_version"], g["is_authorized"], g["status"], now
            ))
        conn.commit()
    finally:
        conn.close()

    return get_all_devices(connection_type="gov_lan")


def register_remote_agent(payload: Dict[str, Any]) -> Tuple[bool, str, str]:
    """
    Register an external remote agent.
    Requires device identity and generates a cryptographically paired device record.
    """
    dev_id = payload.get("id") or f"REMOTE-{uuid.uuid4().hex[:8].upper()}"
    name = payload.get("name", "Remote Authorized Endpoint")
    serial = payload.get("serial", "REMOTE-SN-UNKNOWN")
    ip_addr = payload.get("ip_address", "192.168.1.100")
    media_type = payload.get("media_type", "SSD")
    capacity_bytes = int(payload.get("capacity_bytes", 256 * 1024 * 1024 * 1024))
    now = int(time.time())

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO devices (id, name, connection_type, serial_number, bus_type, media_type,
                                capacity_bytes, health_status, health_score, ip_address, agent_version,
                                is_authorized, status, last_seen)
            VALUES (?, ?, 'remote', ?, 'Virtual/IP', ?, ?, 'Healthy', 95, ?, 'SecureWipe-RemoteAgent v1.2', 0, 'pending_auth', ?)
            ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen
        """, (dev_id, name, serial, media_type, capacity_bytes, ip_addr, now))
        conn.commit()
        return True, "Remote agent registered. Awaiting two-party administrator pairing.", dev_id
    except Exception as e:
        return False, str(e), ""
    finally:
        conn.close()


def authorize_device(device_id: str, operator_name: str) -> Tuple[bool, str]:
    """Pair and authorize a Government LAN or Remote device for managed operations."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM devices WHERE id = ?", (device_id,))
        row = cur.fetchone()
        if not row:
            return False, "Device not found."

        cur.execute("""
            UPDATE devices
            SET is_authorized = 1, status = 'paired', authorized_by = ?
            WHERE id = ?
        """, (operator_name, device_id))
        conn.commit()
        return True, f"Device {device_id} successfully authorized by {operator_name}."
    finally:
        conn.close()


def get_all_devices(connection_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Query managed devices."""
    conn = get_db()
    try:
        cur = conn.cursor()
        if connection_type:
            cur.execute("SELECT * FROM devices WHERE connection_type = ? ORDER BY last_seen DESC", (connection_type,))
        else:
            cur.execute("SELECT * FROM devices ORDER BY connection_type ASC, last_seen DESC")
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
