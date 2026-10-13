# -*- coding: utf-8 -*-
"""
Uniview (UNV) DVR / NVR Log Fetcher & DB Sync - Advanced Filter Edition
-----------------------------------------------------------------------
FEATURES:
 1. Interactive Selection Menu: Choose Time (Hours) & Event Types on the fly!
 2. CLI Flags: `--hours 5`, `--events motion,network`, `--ip 172.17.6.210`, `--limit 1000`, `--auto`.
 3. Fine-Grained Event Filters:
    - 🚨 Motion Detection (Motion Start / Stop / SubType 354, 355)
    - ⚠️ Network Disconnects (Net Broken / LAN / Disconnect / SubType 357, 409)
    - 👤 User Login / Operations (Admin login, Logout, Config changes / SubType 450, 451, 457, 460)
    - 💾 Hard Disk & System Health (S.M.A.R.T Info / Disk Error / Storage / SubType 405, 406, 500)
    - 📹 Video Loss / Camera Tampering / Blind Detect (SubType 350, 351, 352, 353)
    - ❌ System Exceptions (Alarms, Errors, Illegal Access / SubType 404, etc.)
 4. Uniview LAPI (LightAPI) Integration:
    - Endpoints: `/LAPI/V1.0/System/Private/Logs` and `/LAPI/V1.0/System/Logs` via HTTP POST.
    - Full Pagination Support (`Limit` & `Offset` chunking).
    - HTTP Digest Authentication with HTTP Basic Auth fallback.
 5. Complete Raw JSON Storage (`raw_xml` / `raw_json` column).
 6. Thread-Safe Execution with pymysql Connection Pool (PooledDB).
 7. Duplicate Prevention using MySQL INSERT IGNORE.
 8. Formatted Console Table for Single IP and Status Cards for Batch Sync.
"""

import os
import sys
import re
import json
import time
import uuid
import argparse
import threading
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import requests
from requests.auth import HTTPDigestAuth, HTTPBasicAuth
from ping3 import ping

import pymysql
from pymysql.cursors import DictCursor
from dbutils.pooled_db import PooledDB

# ==================================================================== #
#                     USER CONFIGURATION & SETTINGS                    #
# ==================================================================== #

# 1. Scheduler Mode: Set True to run continuously in background loop, False for a single run
ENABLE_AUTO_SCHEDULER    = True     # 🔁 True = Run continuously on schedule, False = Single run
SCHEDULER_INTERVAL_HOURS = 2        # ⏱️ Run synchronization cycle every 2 Hours (7200s)

# 2. Lookback Window: Number of past hours of logs to fetch from DVR
LOOKBACK_HOURS           = 2        # 🕒 Fetch logs from the last 2 Hours (e.g. 2, 5, 24, 72)
DEFAULT_LOOKBACK_HOURS   = LOOKBACK_HOURS

# 3. Event Types to Fetch:
# Options: ["all"] | ["motion"] | ["network"] | ["login"] | ["hdd"] | ["video_loss"] | ["exception"]
EVENT_FILTERS            = ["all"]  # 🎯 Default: Fetch all log event categories

# 4. Target Site Mode:
# None = All Active Uniview Sites (Batch Mode)
# "172.17.6.210" = Target only this specific DVR IP address
TARGET_IP                = None     # 📍 Example: "172.17.6.210" or None for all sites

# 5. Interactive CLI Prompt:
ENABLE_INTERACTIVE_MENU  = False    # 🚫 False = Run directly without prompts, True = Prompt in terminal

# 6. Max Records & Performance Settings:
DEFAULT_MAX_RECORDS      = 5000     # Maximum log records per DVR per cycle
MAX_SITE_THREADS         = 50       # Parallel worker threads for batch sync
DB_MAX_CONNECTIONS       = 70       # MySQL connection pool size

# Database connection settings
DB_HOST = "localhost"
DB_USER = "root"
DB_PASS = ""
DB_NAME = "esurv"

# Network timeouts (seconds)
T_PING          = 3
T_LOG_FETCH     = 12
CYCLE_SLEEP_SECONDS = int(SCHEDULER_INTERVAL_HOURS * 3600)  # Calculated sleep in seconds

# ==================================================================== #
#                        POOL / LOCKS / GLOBALS                        #
# ==================================================================== #

pool = PooledDB(
    creator=pymysql,
    maxconnections=DB_MAX_CONNECTIONS,
    mincached=0,
    maxcached=10,
    maxshared=0,
    blocking=True,
    maxusage=None,
    setsession=[],
    ping=1,
    host=DB_HOST,
    user=DB_USER,
    password=DB_PASS,
    database=DB_NAME,
    charset="utf8mb4",
    cursorclass=DictCursor,
    connect_timeout=10,
    read_timeout=30,
    write_timeout=30,
)

print_lock = threading.Lock()


def get_db_connection():
    return pool.connection()


def safe_print(message):
    with print_lock:
        try:
            print(message, flush=True)
        except UnicodeEncodeError:
            try:
                clean_msg = message.encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8')
                print(clean_msg, flush=True)
            except Exception:
                print(message.encode('ascii', errors='replace').decode('ascii'), flush=True)


def db_execute(sql, params=None, fetch=False, many=False):
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            if many:
                cur.executemany(sql, params or [])
            elif params is not None:
                cur.execute(sql, params)
            else:
                cur.execute(sql)
            if fetch:
                return cur.fetchall()
            conn.commit()
            return cur.rowcount
    except Exception as e:
        safe_print(f"[DB ERROR] {e}\n  SQL: {sql[:120]}")
        return [] if fetch else 0
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ==================================================================== #
#                     DATABASE INITIALIZATION                          #
# ==================================================================== #

def init_log_database():
    """Creates or updates the log storage table with required columns and indexes."""
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS dvr_fetched_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ipaddress VARCHAR(50) NOT NULL,
        atmid VARCHAR(50) DEFAULT NULL,
        dvrname VARCHAR(100) DEFAULT NULL,
        log_time DATETIME NOT NULL,
        major_type VARCHAR(100) DEFAULT NULL,
        minor_type VARCHAR(100) DEFAULT NULL,
        description TEXT DEFAULT NULL,
        source_ip VARCHAR(50) DEFAULT NULL,
        user_name VARCHAR(50) DEFAULT NULL,
        raw_meta_id VARCHAR(255) DEFAULT NULL,
        raw_xml TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_log_time (log_time),
        INDEX idx_ipaddress (ipaddress),
        INDEX idx_atmid (atmid),
        INDEX idx_dvrname (dvrname),
        INDEX idx_major_type (major_type),
        UNIQUE KEY unique_log_idx (ipaddress, log_time, major_type(50), minor_type(50))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    db_execute(create_table_sql)

    try:
        cols_info = db_execute("DESCRIBE dvr_fetched_logs;", fetch=True)
        existing_cols = [c['Field'] for c in cols_info] if cols_info else []
        if "dvrname" not in existing_cols:
            db_execute("ALTER TABLE dvr_fetched_logs ADD COLUMN dvrname VARCHAR(100) DEFAULT NULL AFTER atmid;")
        if "user_name" not in existing_cols:
            db_execute("ALTER TABLE dvr_fetched_logs ADD COLUMN user_name VARCHAR(50) DEFAULT NULL AFTER source_ip;")
        if "raw_meta_id" not in existing_cols:
            db_execute("ALTER TABLE dvr_fetched_logs ADD COLUMN raw_meta_id VARCHAR(255) DEFAULT NULL AFTER user_name;")
        if "raw_xml" not in existing_cols:
            db_execute("ALTER TABLE dvr_fetched_logs ADD COLUMN raw_xml TEXT DEFAULT NULL AFTER raw_meta_id;")

        # Safe check for UNIQUE KEY
        existing_indexes = db_execute("SHOW INDEX FROM dvr_fetched_logs;", fetch=True)
        index_names = [idx['Key_name'] for idx in existing_indexes] if existing_indexes else []
        if "unique_log_idx" not in index_names:
            try:
                db_execute("ALTER TABLE dvr_fetched_logs ADD UNIQUE KEY unique_log_idx (ipaddress, log_time, major_type(50), minor_type(50));")
                safe_print("[SYSTEM] UNIQUE KEY 'unique_log_idx' verified for duplicates prevention.")
            except Exception as ue:
                pass
    except Exception as e:
        safe_print(f"[DB Notice] Schema check: {e}")

    safe_print("[SYSTEM] Database Initialized & 'dvr_fetched_logs' table verified.")


# ==================================================================== #
#                          SITE FETCHING                               #
# ==================================================================== #

def get_uniview_sites(target_ip=None):
    """Fetches Uniview (UNV) sites from database tables."""
    if target_ip:
        sites = db_execute("""
            SELECT SN, atmid, IPAddress AS ipaddress, port, UserName AS username, Password AS password, dvrname
            FROM all_dvr_live
            WHERE IPAddress = %s
        """, (target_ip,), fetch=True)
        if not sites:
            sites = db_execute("""
                SELECT SN, ATMID AS atmid, DVRIP AS ipaddress, COALESCE(dvr_port, router_port, 81) AS port, UserName AS username, Password AS password, DVRName AS dvrname
                FROM sites
                WHERE DVRIP = %s
            """, (target_ip,), fetch=True)
        return sites or []

    # Search for UNV / Uniview variations
    sites = db_execute("""
        SELECT SN, atmid, IPAddress AS ipaddress, port, UserName AS username, Password AS password, dvrname
        FROM all_dvr_live
        WHERE (
            LOWER(dvrname) LIKE '%unv%'
            OR LOWER(dvrname) LIKE '%uniview%'
        ) 
        AND IPAddress IS NOT NULL 
        AND TRIM(IPAddress) != ''
        AND live = 'Y'
    """, fetch=True)

    if not sites:
        sites = db_execute("""
            SELECT SN, ATMID AS atmid, DVRIP AS ipaddress, COALESCE(dvr_port, router_port, 81) AS port, UserName AS username, Password AS password, DVRName AS dvrname
            FROM sites
            WHERE (
                LOWER(DVRName) LIKE '%unv%'
                OR LOWER(DVRName) LIKE '%uniview%'
            ) 
            AND DVRIP IS NOT NULL 
            AND TRIM(DVRIP) != ''
            AND live = 'Y'
        """, fetch=True)
    return sites or []


# ==================================================================== #
#                        LOGS PARSING & FILTERS                        #
# ==================================================================== #

def clean_log_time(time_val):
    """Converts UNV timestamp (Unix Epoch seconds or ISO string) to MySQL DATETIME format."""
    if not time_val:
        return None
    try:
        # Check if integer epoch timestamp
        if isinstance(time_val, (int, float)):
            return datetime.fromtimestamp(int(time_val)).strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(time_val, str) and time_val.strip().isdigit():
            return datetime.fromtimestamp(int(time_val.strip())).strftime("%Y-%m-%d %H:%M:%S")

        cleaned = str(time_val).strip().replace("T", " ").replace("Z", "")
        if "+" in cleaned:
            cleaned = cleaned.split("+")[0]
        dt = datetime.strptime(cleaned[:19], "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        m = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", str(time_val))
        if m:
            return m.group(1)
        return str(time_val).strip()[:19] if time_val else None


# ==================================================================== #
#                  UNIVIEW (UNV) LOG TYPE MAPPINGS                     #
# ==================================================================== #

UNV_MAIN_TYPES = {
    0: "All",
    1: "Alarm",
    2: "Alert",
    3: "Operation",
    4: "Information",
}

UNV_SUB_TYPES = {
    # MainType 1: Alarm
    1: {
        350: "Motion Detection Started",
        351: "Motion Detection Ended",
        352: "Video Loss Started",
        353: "Video Loss Ended",
        354: "Tampering Detection Started",
        355: "Tampering Detection Ended",
        356: "Input Alarm Started",
        357: "Input Alarm Ended",
        360: "Audio Detection Started",
        361: "Audio Detection Ended",
        362: "Cross Line Detection Alarm",
        363: "Face Detection Alarm",
        364: "Intrusion Detection Alarm",
        368: "POS Alarm",
        370: "Defocus Detection Started",
        371: "Defocus Detection Ended",
        372: "Scene Change Alarm",
        374: "Auto Tracking Started",
        375: "Auto Tracking Ended",
    },
    # MainType 2: Exception
    2: {
        401: "Disk Offline",
        402: "Disk Abnormal",
        405: "Scheduled Recording Failure",
        406: "Scheduled Recording Failure Cleared",
        407: "Illegal Access",
        408: "IP Conflict",
        409: "Network Disconnected",
        415: "Running Out of Recording Space",
        416: "Running Out of Image Space",
        417: "Recording Space Used Up",
        418: "Image Space Used Up",
        421: "Array Damaged",
        422: "Array Degraded",
        423: "Recording/Snapshot Abnormal",
        424: "Network Disconnected Cleared",
        425: "IP Conflict Cleared",
    },
    # MainType 3: Operation
    3: {
        450: "Login",
        451: "Logout",
        452: "Add User",
        453: "Delete User",
        454: "Modify User",
        455: "Start Recording",
        456: "End Recording",
        457: "Playback/Download",
        458: "Download",
        459: "Control PTZ",
        460: "Preview Live View",
        461: "Start Patrol Recording",
        462: "End Patrol Recording",
        463: "Start Two-Way Audio",
        464: "Stop Two-Way Audio",
        465: "Add IP Camera",
        466: "Delete IP Camera",
        467: "Modify IP Camera",
        468: "Quick Add IP Camera",
        469: "Add IP Camera by Network Segment",
        470: "Modify IP Camera IP Addr.",
        472: "Recording Backup",
        473: "Set Audio Detection",
        474: "Search Extended Disk",
        475: "Add Extended Disk",
        476: "Delete Extended Disk",
        477: "Set Extended Disk",
        478: "Live View by Multicast",
        479: "Mount Extended Disk",
        480: "Unmount Extended Disk",
        481: "Force User Offline",
        500: "Set Basic Device Info",
        501: "Set System Time",
        502: "Set Device Serial",
        503: "Set OSD",
        504: "Set Camera Name",
        505: "Set Video Encoding",
        506: "Set Image Parameters",
        507: "PTZ Configuration",
        508: "Set Preset Patrol",
        509: "Set Preset",
        510: "Set Recording Schedule",
        511: "Set Motion Detection",
        512: "Set Video Loss",
        513: "Set Video Tampering",
        514: "Set Privacy Mask",
        515: "Set OSD Content",
        516: "Set Alarm Input",
        517: "Set Alarm Output",
        518: "Enable Alarm Output",
        519: "Disable Alarm Output",
        520: "Alert",
        521: "Set Hard Disk",
        522: "Set TCP/IP",
        523: "Set PPPoE",
        524: "Set Port",
        526: "Set Preview on NVR",
        527: "Set Email",
        528: "Test Email",
        529: "Set IP Control",
        530: "Set Port Mapping",
        531: "Add Tag",
        532: "Delete Tag",
        533: "Modify Tag",
        534: "Lock Recording",
        535: "Unlock Recording",
        536: "DDNS Configuration",
        537: "DDNS Update Succeeded",
        538: "DDNS Update Failed due to Incorrect Username or Password",
        539: "DDNS Update Failed. The Domain Name Doesn't Exist.",
        540: "DDNS Update Failed",
        541: "Set HTTPS",
        542: "IP Camera Offline Alarm Configuration",
        543: "Set Telnet",
        544: "DDNS Domain Name Test",
        545: "DDNS Domain Name Conflict",
        546: "Invalid DDNS Domain Name",
        547: "Delete Preset",
        551: "PTZ 3D Positioning",
        552: "Set Snapshot Schedule",
        553: "Set Image Upload Schedule",
        554: "Set FTP Server",
        555: "Test FTP Server Connection",
        556: "Start Manual Snapshot",
        557: "Stop Manual Snapshot",
        558: "Set Snapshot",
        559: "Add Holiday",
        560: "Delete Holiday",
        561: "Modify Holiday",
        562: "Enable/Disable Holiday",
        563: "Allocate Space",
        564: "HDD Full Policy Configuration",
        565: "Set Audio Stream",
        566: "Set Array Property",
        567: "Set Hot Spare Disk",
        568: "Create Array",
        569: "Create Array by One-Click",
        570: "Rebuild Array",
        571: "Delete Array",
        572: "Enable RAID",
        573: "Disable RAID",
        574: "S.M.A.R.T. Test",
        575: "Set S.M.A.R.T.",
        576: "Bad Sector Detect",
        577: "Set Audio Alarm Duration",
        578: "Clear Audio Alarm",
        581: "Set Camera Time Sync",
        582: "Enable Disk Group",
        583: "Disable Disk Group",
        584: "Set ONVIF Authentication",
        585: "Set 802.1x",
        586: "Set ARP Protection",
        587: "Set Smart Basic Info",
        588: "Set Cross Line Detection",
        589: "Set Intrusion Detection",
        590: "Set People Counting",
        591: "Set Face Detection",
        593: "Set Fisheye",
        594: "Custom Protocol",
        595: "Behavior Search",
        596: "Face Search",
        597: "People Counting",
        598: "VCA Backup",
        599: "3G/4G Configuration",
        600: "Startup",
        601: "Shutdown",
        602: "Restart",
        603: "Upgrade",
        604: "Export Diagnosis Information",
        605: "Export Configuration File",
        606: "Import Configuration File",
        607: "Restore Defaults",
        608: "Restore Factory Defaults",
        609: "Auto-Function",
        610: "Camera Upgrade",
        611: "Restore Camera Defaults",
        612: "Add Transaction Settings",
        613: "Modify Transaction Settings",
        614: "Delete Transaction Settings",
        615: "Set POS OSD",
        618: "Export History Diagnosis Info",
        700: "Add Hot Spare Device",
        701: "Delete Hot Spare Device",
        702: "Modify Hot Spare Device",
        703: "Delete Working Device",
        704: "Set Working Mode to Normal",
        705: "Set Working Mode to Hot Spare",
        706: "Set Auto Guard",
        707: "Set Multicast",
        708: "Set Defocus Detection",
        709: "Set Scene Change Detection",
        711: "Set Auto Tracking",
        712: "Sort Camera",
        713: "Set Watermark",
        716: "Set Security Password",
        721: "Disable Exclusive Smart Function",
    },
    # MainType 4: Information / Storage
    4: {
        400: "HDD Info",
        401: "Format HDD",
        402: "SMART Info",
        500: "Run Status Info",
    }
}


def map_unv_log_types(main_type_val, sub_type_val):
    """
    Maps Uniview numeric MainType and SubType codes to human-readable strings
    matching the DVR Web Interface (e.g. Alarm, Operation, Login, Tampering Detection).
    """
    try:
        main_int = int(str(main_type_val).strip())
    except (ValueError, TypeError):
        main_int = None

    try:
        sub_int = int(str(sub_type_val).strip())
    except (ValueError, TypeError):
        sub_int = None

    # Resolve Major Type
    if main_int in UNV_MAIN_TYPES:
        major = UNV_MAIN_TYPES[main_int]
    elif str(main_type_val).strip() in ["Alarm", "Exception", "Operation", "Information", "Storage"]:
        major = str(main_type_val).strip()
    elif main_type_val:
        major = str(main_type_val).strip()
    else:
        major = "General"

    # Resolve Minor Type
    minor = None
    if main_int in UNV_SUB_TYPES and sub_int in UNV_SUB_TYPES[main_int]:
        minor = UNV_SUB_TYPES[main_int][sub_int]
    else:
        for cat_dict in UNV_SUB_TYPES.values():
            if sub_int in cat_dict:
                minor = cat_dict[sub_int]
                break

    if not minor:
        minor = str(sub_type_val).strip() if sub_type_val is not None and str(sub_type_val).strip() else major

    return major, minor


def parse_unv_log_records(data_payload, ip: str):
    """
    Parses Uniview LAPI JSON response dynamically.
    Translates numeric MainType and SubType into descriptive human-readable strings.
    """
    if isinstance(data_payload, str):
        try:
            data_payload = json.loads(data_payload)
        except Exception:
            return []

    if not isinstance(data_payload, dict):
        return []

    # Extract logs array from various Uniview JSON envelope variants
    logs_array = None
    if "Response" in data_payload and isinstance(data_payload["Response"], dict):
        resp = data_payload["Response"]
        if "Data" in resp and isinstance(resp["Data"], dict):
            logs_array = resp["Data"].get("Logs")
        elif "Logs" in resp:
            logs_array = resp.get("Logs")
    elif "Data" in data_payload and isinstance(data_payload["Data"], dict):
        logs_array = data_payload["Data"].get("Logs")
    elif "Logs" in data_payload and isinstance(data_payload["Logs"], list):
        logs_array = data_payload.get("Logs")

    if not logs_array or not isinstance(logs_array, list):
        return []

    parsed_records = []
    for item in logs_array:
        if not isinstance(item, dict):
            continue

        raw_time = item.get("Time") or item.get("LogTime") or item.get("time") or ""
        cleaned_time = clean_log_time(raw_time)
        if not cleaned_time:
            continue

        # Extract dynamic fields directly from DVR payload
        main_type_val = item.get("MainType", item.get("mainType", item.get("Type", "")))
        sub_type_val = item.get("SubType", item.get("subType", item.get("subtype", "")))
        channel_id = str(item.get("ID") or item.get("ChannelID") or item.get("Channel") or "").strip()
        user_val = str(item.get("LoginName") or item.get("UserName") or item.get("User") or "").strip()
        src_ip_val = str(item.get("IP") or item.get("IpAddress") or item.get("SourceIp") or "").strip()
        detail_val = str(item.get("DetailInfo") or item.get("Detail") or item.get("OperObject") or "").strip()

        # Map numeric codes to human-readable names (e.g. 1 -> "Alarm", 354 -> "Tampering Detection Started")
        major, minor = map_unv_log_types(main_type_val, sub_type_val)

        # Build dynamic description based on available fields from the DVR
        desc_parts = []
        if detail_val:
            desc_parts.append(detail_val)
        if channel_id and channel_id != "0":
            desc_parts.append(f"Channel: {channel_id}")
        if user_val:
            desc_parts.append(f"User: {user_val}")
        if src_ip_val and src_ip_val != "0.0.0.0":
            desc_parts.append(f"IP: {src_ip_val}")

        description = " | ".join(desc_parts) if desc_parts else minor

        parsed_records.append({
            "ipaddress": ip,
            "log_time": cleaned_time,
            "major_type": major,
            "minor_type": minor,
            "description": description,
            "source_ip": src_ip_val if src_ip_val != "0.0.0.0" else "",
            "user_name": user_val,
            "raw_meta_id": f"unv/{major}/{minor}/{channel_id}"[:250],
            "raw_xml": json.dumps(item, separators=(',', ':'))
        })

    return parsed_records


def matches_event_filter(record: dict, filter_keywords: list) -> bool:
    """Checks if a log entry matches the requested event filters."""
    if not filter_keywords or "all" in [f.lower() for f in filter_keywords] or "*" in filter_keywords:
        return True

    text_corpus = (
        f"{record.get('major_type', '')} "
        f"{record.get('minor_type', '')} "
        f"{record.get('description', '')} "
        f"{record.get('raw_meta_id', '')} "
        f"{record.get('raw_xml', '')}"
    ).lower()

    for ef in filter_keywords:
        ef_clean = ef.strip().lower()
        if not ef_clean:
            continue
        if ef_clean in ["all", "*"]:
            return True
        elif ef_clean in ["motion", "motion_detection", "motion start", "motion stop", "md", "352", "353"]:
            if "motion" in text_corpus or "md" in text_corpus or "detect" in text_corpus or "352" in text_corpus or "353" in text_corpus:
                return True
        elif ef_clean in ["tamper", "tampering", "tamper start", "tamper stop", "354", "355"]:
            if "tamper" in text_corpus or "354" in text_corpus or "355" in text_corpus:
                return True
        elif ef_clean in ["network", "net", "net_broken", "lan", "disconnect", "357", "358", "409", "424"]:
            if "net broken" in text_corpus or "network" in text_corpus or "lan" in text_corpus or "disconnect" in text_corpus or "ip conflict" in text_corpus or "409" in text_corpus or "424" in text_corpus:
                return True
        elif ef_clean in ["login", "user_login", "auth", "operation", "user", "account", "450", "451", "457", "460"]:
            if "login" in text_corpus or "logout" in text_corpus or "user" in text_corpus or "account" in text_corpus or "operation" in text_corpus or "admin" in text_corpus or "cfg" in text_corpus or "config" in text_corpus or "450" in text_corpus or "451" in text_corpus or "457" in text_corpus or "460" in text_corpus:
                return True
        elif ef_clean in ["hdd", "disk", "smart", "smart info", "storage", "health", "status", "400", "405", "406", "500"]:
            if "smart" in text_corpus or "disk" in text_corpus or "hdd" in text_corpus or "storage" in text_corpus or "run status" in text_corpus or "400" in text_corpus or "405" in text_corpus or "406" in text_corpus or "500" in text_corpus:
                return True
        elif ef_clean in ["video_loss", "videoloss", "video", "blind", "350", "351"]:
            if "video loss" in text_corpus or "videoloss" in text_corpus or "blind" in text_corpus or "350" in text_corpus or "351" in text_corpus:
                return True
        elif ef_clean in ["exception", "alarm", "404", "error", "fail"]:
            if "exception" in text_corpus or "alarm" in text_corpus or "error" in text_corpus or "fail" in text_corpus or "illegal" in text_corpus:
                return True
        elif ef_clean in text_corpus:
            return True

    return False


def format_http_error(status_code: int) -> str:
    if status_code == 401:
        return "Invalid Username/Password (HTTP 401 Unauthorized)"
    elif status_code == 403:
        return "Access Forbidden (HTTP 403)"
    elif status_code == 404:
        return "LAPI Logs Endpoint Not Found (HTTP 404)"
    elif status_code == 400:
        return "Bad Request Format (HTTP 400)"
    elif status_code == 500:
        return "DVR Internal Error (HTTP 500)"
    return f"HTTP Error Status {status_code}"


# ==================================================================== #
#                        LOGS FETCHING CLASS                           #
# ==================================================================== #

class UniviewLogFetcher:
    def __init__(self, ip, port, username, password):
        self.ip = ip
        self.port = int(port or 81)
        self.username = username or "admin"
        self.password = password or "admin123"
        self.base_url = f"http://{self.ip}:{self.port}"

        self.session = requests.Session()
        # Uniview LAPI utilizes HTTP Digest Auth; fallback to Basic Auth if necessary
        self.session.auth = HTTPDigestAuth(self.username, self.password)
        self.session.headers.update({
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "User-Agent": "UNV-LAPI-Client/1.0"
        })

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass

    def check_ping(self):
        try:
            p = ping(self.ip, timeout=T_PING)
            if p is not None and p is not False:
                return True
        except Exception:
            pass
        # Fallback TCP check on HTTP port
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(T_PING)
            res = s.connect_ex((self.ip, self.port))
            s.close()
            return res == 0
        except Exception:
            return False

    def get_device_time(self):
        """Attempts to retrieve current device clock from Uniview LAPI."""
        try:
            r = self.session.get(f"{self.base_url}/LAPI/V1.0/System/Time", timeout=5)
            if r.status_code == 200:
                data = r.json().get("Response", {}).get("Data", {})
                d_time = data.get("DeviceTime")
                if d_time and isinstance(d_time, (int, float)):
                    return int(d_time)
        except Exception:
            pass
        return None

    def fetch_logs(self, start_time_dt, end_time_dt, event_filters=None, max_records=DEFAULT_MAX_RECORDS):
        """
        Fetches system logs from Uniview (UNV) DVR/NVR using LightAPI (LAPI).
        Endpoints:
          1. /LAPI/V1.0/System/Private/Logs
          2. /LAPI/V1.0/System/Logs
        Payload requires exact QryType / QryCondition parameters:
          QryType 4 (Time) with QryCondition 3 (>=) and 4 (<=)
          QryType 5 (MainType) and QryType 6 (SubType)
        """
        # Align with device clock if available to prevent timezone/clock skew issues
        dev_time = self.get_device_time()
        lookback_seconds = int((end_time_dt - start_time_dt).total_seconds())
        if dev_time:
            end_ts = dev_time
            start_ts = dev_time - lookback_seconds
        else:
            end_ts = int(end_time_dt.timestamp())
            start_ts = int(start_time_dt.timestamp())

        endpoints = [
            f"{self.base_url}/LAPI/V1.0/System/Private/Logs",
            f"{self.base_url}/LAPI/V1.0/System/Logs",
        ]

        # Determine MainType and SubType filter values
        main_type_filter = "0"
        sub_type_filter = "0"
        if event_filters and "all" not in [f.lower() for f in event_filters] and "*" not in event_filters:
            if any(k in event_filters for k in ["motion", "video_loss", "tamper", "alarm"]):
                main_type_filter = "1"
            elif any(k in event_filters for k in ["login", "operation", "user", "config"]):
                main_type_filter = "3"
            elif any(k in event_filters for k in ["exception", "network", "hdd", "disk", "smart"]):
                main_type_filter = "2"

        active_endpoint = None
        records = []
        chunk_size = 100
        offset = 0

        # Try endpoints to find working LAPI interface
        for ep in endpoints:
            payload = {
                "Num": 4,
                "QueryInfos": [
                    {"QryType": 4, "QryCondition": 3, "QryData": str(start_ts)},
                    {"QryType": 4, "QryCondition": 4, "QryData": str(end_ts)},
                    {"QryType": 5, "QryCondition": 0, "QryData": main_type_filter},
                    {"QryType": 6, "QryCondition": 0, "QryData": sub_type_filter},
                ],
                "Limit": chunk_size,
                "Offset": 0
            }

            try:
                r = self.session.post(ep, json=payload, timeout=T_LOG_FETCH)
                
                # 401 Unauthorized -> Try Basic Auth fallback
                if r.status_code == 401:
                    self.session.auth = HTTPBasicAuth(self.username, self.password)
                    r = self.session.post(ep, json=payload, timeout=T_LOG_FETCH)

                if r.status_code == 200:
                    res_json = r.json()
                    resp_obj = res_json.get("Response", {})
                    # If device returned business error in JSON
                    if resp_obj.get("ResponseCode") != 0 and resp_obj.get("StatusCode") == 401:
                        return False, format_http_error(401), []

                    active_endpoint = ep
                    chunk_records = parse_unv_log_records(r.text, self.ip)
                    for rec in chunk_records:
                        if event_filters and not matches_event_filter(rec, event_filters):
                            continue
                        records.append(rec)
                        if len(records) >= max_records:
                            break

                    data_block = resp_obj.get("Data", {}) or res_json.get("Data", {})
                    total_count = data_block.get("Total") or data_block.get("Num")

                    if len(chunk_records) < chunk_size or (total_count and len(records) >= total_count):
                        return True, "Success", records[:max_records]

                    offset += len(chunk_records)
                    break
                elif r.status_code in [401, 403]:
                    return False, format_http_error(r.status_code), []
            except requests.exceptions.Timeout:
                return False, "Connection Timeout", []
            except Exception:
                pass

        if not active_endpoint:
            return False, "Uniview LAPI Endpoint Unavailable or Invalid Auth", []

        # Paginate remaining records
        try:
            while len(records) < max_records:
                payload = {
                    "Num": 4,
                    "QueryInfos": [
                        {"QryType": 4, "QryCondition": 3, "QryData": str(start_ts)},
                        {"QryType": 4, "QryCondition": 4, "QryData": str(end_ts)},
                        {"QryType": 5, "QryCondition": 0, "QryData": main_type_filter},
                        {"QryType": 6, "QryCondition": 0, "QryData": sub_type_filter},
                    ],
                    "Limit": min(chunk_size, max_records - len(records)),
                    "Offset": offset
                }

                r_page = self.session.post(active_endpoint, json=payload, timeout=T_LOG_FETCH)
                if r_page.status_code != 200:
                    break

                page_records = parse_unv_log_records(r_page.text, self.ip)
                if not page_records:
                    break

                for rec in page_records:
                    if event_filters and not matches_event_filter(rec, event_filters):
                        continue
                    records.append(rec)
                    if len(records) >= max_records:
                        break

                if len(page_records) < chunk_size:
                    break
                offset += len(page_records)

        except Exception as e:
            if not records:
                return False, str(e), []

        return True, "Success", records[:max_records]


# ==================================================================== #
#                          SITE PROCESSOR                              #
# ==================================================================== #

def build_log_card(ip, atm_id, status, message, fetched_count=0, saved_count=0):
    """Returns a clean console output status card."""
    ip_str = str(ip or 'Unknown')
    card = [
        "=" * 70,
        f"📜  UNIVIEW (UNV) LOG SYNC | IP: {ip_str:<15} | ATM ID: {atm_id or 'N/A'}",
        "-" * 70,
        f"  📶 Status       : {status}",
        f"  💬 Message      : {message}",
    ]
    if status == "✅ Success":
        card.append(f"  📥 Fetched Logs : {fetched_count} entries")
        card.append(f"  💾 Inserted     : {saved_count} new entries (duplicates auto-ignored)")
    card.append("=" * 70)
    return "\n".join(card)


def process_site_logs(site, lookback_hours=DEFAULT_LOOKBACK_HOURS, event_filters=None, max_records=DEFAULT_MAX_RECORDS, is_single=False):
    ip = str(site.get("ipaddress") or "").strip()
    if not ip:
        return False
    port = site.get("port") or 81
    user = site.get("username")
    pwd = site.get("password")
    atm_id = str(site.get("atmid", "") or "").replace(" ", "")
    dvr_name = str(site.get("dvrname") or "UNV").strip()

    fetcher = UniviewLogFetcher(ip, port, user, pwd)

    try:
        # 1. Ping Check
        if not fetcher.check_ping():
            safe_print(build_log_card(ip, atm_id, "❌ Offline", "Device ping / connection timeout."))
            return False

        # 2. Lookback time range
        now_dt = datetime.now()
        start_time = now_dt - timedelta(hours=lookback_hours)
        end_time = now_dt
        filter_desc = f"Events: {','.join(event_filters)}" if event_filters and "all" not in event_filters else "All Events"
        message = f"Last {lookback_hours} hours scan ({start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%H:%M')}) [{filter_desc}]"

        # 3. Fetch from DVR with event filter
        success, err_msg, logs_list = fetcher.fetch_logs(start_time, end_time, event_filters=event_filters, max_records=max_records)
        if not success:
            safe_print(build_log_card(ip, atm_id, "❌ API Failed", f"{err_msg} ({message})"))
            return False

        # 4. Insert logs into MySQL database using INSERT IGNORE
        saved_count = 0
        if logs_list:
            insert_sql = """
                INSERT IGNORE INTO dvr_fetched_logs 
                (ipaddress, atmid, dvrname, log_time, major_type, minor_type, description, source_ip, user_name, raw_meta_id, raw_xml)
                VALUES (%(ipaddress)s, %(atmid)s, %(dvrname)s, %(log_time)s, %(major_type)s, %(minor_type)s, %(description)s, %(source_ip)s, %(user_name)s, %(raw_meta_id)s, %(raw_xml)s)
            """
            for log in logs_list:
                log["atmid"] = atm_id
                log["dvrname"] = dvr_name

            saved_count = db_execute(insert_sql, logs_list, many=True)

        safe_print(build_log_card(ip, atm_id, "✅ Success", message, len(logs_list), saved_count))

        # If single site mode, display detailed log table in console
        if is_single and logs_list:
            safe_print(f"\n{'='*110}")
            safe_print(f" {'No.':<4} | {'Date & Time':<19} | {'Category':<12} | {'User':<10} | {'Event & Details':<55}")
            safe_print(f"{'-'*110}")
            for idx, item in enumerate(logs_list, 1):
                dt = str(item.get('log_time', ''))[:19]
                cat = str(item.get('major_type', ''))[:12]
                u = str(item.get('user_name', '') or '-')[:10]
                ev = f"{item.get('minor_type', '')} - {item.get('description', '')}"[:55]
                safe_print(f" {idx:<4} | {dt:<19} | {cat:<12} | {u:<10} | {ev:<55}")
            safe_print(f"{'='*110}\n")

        return True

    except Exception as e:
        safe_print(f"❌ process_site_logs Exception for {ip}: {e}")
        return False
    finally:
        fetcher.close()


# ==================================================================== #
#                       INTERACTIVE CLI PROMPT                         #
# ==================================================================== #

def prompt_user_filters():
    print("""
============================================================
 🕒 STEP 1: SELECT LOG LOOKBACK TIME WINDOW
============================================================
 [1] Past 1 Hour
 [2] Past 3 Hours
 [3] Past 5 Hours  - [Default]
 [4] Past 12 Hours
 [5] Past 24 Hours (1 Day)
 [6] Past 48 Hours (2 Days)
 [7] Past 7 Days
 [8] Custom Hours Input
""")
    try:
        t_choice = input("Enter Choice (1-8) [Default: 3]: ").strip()
    except (EOFError, KeyboardInterrupt):
        t_choice = "3"

    hours_map = {
        "1": 1,
        "2": 3,
        "3": 5,
        "4": 12,
        "5": 24,
        "6": 48,
        "7": 168,
    }

    if t_choice == "8":
        try:
            val = input("Enter number of hours (e.g. 10): ").strip()
            hours = int(val) if val.isdigit() else DEFAULT_LOOKBACK_HOURS
        except Exception:
            hours = DEFAULT_LOOKBACK_HOURS
    else:
        hours = hours_map.get(t_choice, DEFAULT_LOOKBACK_HOURS)

    print(f"-> Selected: Past {hours} Hours\n")

    print("""
============================================================
 🎯 STEP 2: SELECT EVENT FILTER
============================================================
 [1] All Events (Full Uniview Logs) - [Default]
 [2] 🚨 Motion Detection (Motion Start / Stop / 352, 353)
 [3] ⚠️ Network Disconnects (Net Broken / LAN / Disconnect / 409, 424)
 [4] 👤 User Login / Operations (Admin logins, Settings, Operations / 450, 451)
 [5] 💾 Hard Disk & System Health (S.M.A.R.T Info / Storage / Disk / 400)
 [6] 📹 Video Loss & Tampering (Video Loss / Blind / Tampering / 354, 355)
 [7] ❌ System Exceptions (All Exception Errors & Alarms)
 [8] Multiple Selection / Custom Filter (e.g. 2,3,5)
""")
    try:
        e_choice = input("Enter Choice (1-8) [Default: 1]: ").strip()
    except (EOFError, KeyboardInterrupt):
        e_choice = "1"

    events = []
    if e_choice in ["", "1"]:
        events = ["all"]
    elif e_choice == "2":
        events = ["motion"]
    elif e_choice == "3":
        events = ["network"]
    elif e_choice == "4":
        events = ["login"]
    elif e_choice == "5":
        events = ["hdd", "smart"]
    elif e_choice == "6":
        events = ["video_loss", "tamper"]
    elif e_choice == "7":
        events = ["exception"]
    elif e_choice == "8":
        try:
            custom_in = input("Enter multiple options (e.g. 2,3,5) or keywords: ").strip()
            num_map = {
                "2": "motion",
                "3": "network",
                "4": "login",
                "5": "hdd",
                "6": "video_loss",
                "7": "exception"
            }
            parts = [p.strip() for p in custom_in.replace(",", " ").split()]
            for p in parts:
                if p in num_map:
                    events.append(num_map[p])
                else:
                    events.append(p)
            if not events:
                events = ["all"]
        except Exception:
            events = ["all"]
    else:
        events = ["all"]

    print(f"-> Selected Events: {', '.join(events)}\n")

    print("""
============================================================
 📍 STEP 3: SELECT TARGET SITE MODE
============================================================
 [1] All Uniview (UNV) Sites (Batch Sync) - [Default]
 [2] Single IP Test Mode
""")
    try:
        s_choice = input("Enter Choice (1-2) [Default: 1]: ").strip()
    except (EOFError, KeyboardInterrupt):
        s_choice = "1"

    target_ip = None
    if s_choice == "2":
        try:
            target_ip = input("Enter Uniview DVR IP address (e.g. 172.17.6.210): ").strip()
        except Exception:
            target_ip = None

    return hours, events, target_ip


# ==================================================================== #
#                              MAIN LOOP                               #
# ==================================================================== #

def main():
    parser = argparse.ArgumentParser(description="Uniview (UNV) DVR / NVR Log Fetcher & DB Sync")
    parser.add_argument("--ip", "-i", type=str, default=TARGET_IP, help="Target a specific DVR IP address")
    parser.add_argument("--hours", "-H", type=int, default=LOOKBACK_HOURS, help=f"Lookback hours to fetch (default: {LOOKBACK_HOURS})")
    parser.add_argument("--events", "-e", type=str, help="Event filter comma-separated (e.g. --events motion,network,login,hdd,all)")
    parser.add_argument("--limit", "-l", type=int, default=DEFAULT_MAX_RECORDS, help=f"Max log records to fetch (default: {DEFAULT_MAX_RECORDS})")
    parser.add_argument("--auto", "-a", action="store_true", default=ENABLE_AUTO_SCHEDULER, help="Run automatically in scheduler mode")
    parser.add_argument("--menu", "-m", action="store_true", default=ENABLE_INTERACTIVE_MENU, help="Open interactive selection menu")
    args = parser.parse_args()

    init_log_database()

    # Determine execution settings from CLI or Config
    hours = args.hours if args.hours is not None else LOOKBACK_HOURS
    if args.events:
        events = [e.strip().lower() for e in args.events.split(",")]
    else:
        events = EVENT_FILTERS or ["all"]
    target_ip = args.ip.strip() if args.ip else TARGET_IP
    auto_loop = args.auto

    # Show interactive menu ONLY if explicitly requested via config or --menu
    if args.menu and sys.stdin.isatty():
        hours, events, target_ip = prompt_user_filters()

    # SINGLE IP MODE
    if target_ip:
        safe_print(f"\n{'='*70}")
        safe_print(f"🎯 SINGLE UNIVIEW (UNV) SITE INSPECTION MODE: IP {target_ip}")
        safe_print(f"🕒 Time Range: Last {hours} Hours | Filter: {', '.join(events)}")
        safe_print(f"{'='*70}\n")

        sites = get_uniview_sites(target_ip=target_ip)
        if not sites:
            site = {"ipaddress": target_ip, "port": 81, "username": "admin", "password": "password", "atmid": "SINGLE_TEST", "dvrname": "UNV"}
        else:
            site = sites[0]

        process_site_logs(site, lookback_hours=hours, event_filters=events, max_records=args.limit, is_single=True)
        return

    # BATCH SCHEDULER MODE (All Sites)
    filter_label = ", ".join(events) if events else "All Events"
    cycle_num = 1

    while True:
        start_time = datetime.now()
        start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")

        safe_print("\n" + "=" * 70)
        safe_print(f"🚀 [CYCLE #{cycle_num}] UNIVIEW (UNV) DVR LOG FETCH STARTED AT {start_str}")
        safe_print(f"🕒 Lookback: Last {hours} Hours | 🎯 Events Filter: {filter_label}")
        safe_print(f"⏱️ Schedule Interval: Every {SCHEDULER_INTERVAL_HOURS} Hours | 🔁 Auto-Loop: {'ON' if auto_loop else 'OFF'}")
        safe_print("=" * 70 + "\n")

        sites = get_uniview_sites()

        if not sites:
            safe_print("⚠️ No Active Uniview (UNV) sites found in database.")
        else:
            safe_print(f"📋 Loaded {len(sites)} Uniview (UNV) sites for log inspection. "
                       f"Running with {MAX_SITE_THREADS} parallel threads (Last {hours} hours)...\n")

            succ = fail = 0
            with ThreadPoolExecutor(max_workers=MAX_SITE_THREADS) as ex:
                futures = {ex.submit(process_site_logs, s, hours, events, args.limit, False): s for s in sites}
                for fut in concurrent.futures.as_completed(futures):
                    try:
                        if fut.result():
                            succ += 1
                        else:
                            fail += 1
                    except Exception as e:
                        fail += 1
                        safe_print(f"❌ Worker Thread Error: {e}")

            end_time = datetime.now()
            duration = round((end_time - start_time).total_seconds(), 1)
            next_run = (end_time + timedelta(seconds=CYCLE_SLEEP_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")

            safe_print("\n".join([
                "\n" + "=" * 70,
                f"📊 [CYCLE #{cycle_num}] UNIVIEW (UNV) LOG EXTRACTION SUMMARY",
                "=" * 70,
                f"  ⏱️  Started At     : {start_str}",
                f"  ⏱️  Finished At    : {end_time.strftime('%Y-%m-%d %H:%M:%S')} (Duration: {duration}s)",
                f"  📍 Total Devices  : {len(sites)}",
                f"  🟢 Sync Completed : {succ} DVRs",
                f"  🔴 Sync Failed    : {fail} DVRs",
                "=" * 70,
                f"  ⏳ Next log sync at: {next_run} (after {SCHEDULER_INTERVAL_HOURS} hours)",
                "=" * 70 + "\n",
            ]))

        # If user disabled auto scheduler, exit after 1 cycle
        if not auto_loop:
            safe_print("ℹ️ Auto-scheduler is OFF. Completed single batch sync.")
            break

        elapsed = (datetime.now() - start_time).total_seconds()
        sleep_for = max(60, CYCLE_SLEEP_SECONDS - elapsed)
        safe_print(f"😴 Sleeping for {int(sleep_for)}s ({round(sleep_for/3600, 2)} hrs) until next automated cycle...\n")
        
        cycle_num += 1
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
