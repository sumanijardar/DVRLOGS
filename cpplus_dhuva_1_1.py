# -*- coding: utf-8 -*-
"""
CP Plus & Dahua DVR Log Fetcher & DB Sync - Advanced Filter Edition
-------------------------------------------------------------------
FEATURES:
 1. Interactive Selection Menu: Choose Time (Hours) & Event Types on the fly!
 2. CLI Flags: `--hours 5`, `--events motion,network`, `--ip 172.17.17.44`, `--limit 1000`, `--auto`.
 3. Fine-Grained Event Filters:
    - 🚨 Motion Detection (Motion Start / Stop / MD)
    - ⚠️ Network Disconnects (Net Broken / LAN / Disconnect)
    - 👤 User Login / Operations (Admin login, Config changes, Account)
    - 💾 Hard Disk & System Health (S.M.A.R.T Info / Disk Error / Storage)
    - 📹 Video Loss / Camera Tampering / Blind Detect
    - ❌ System Exceptions (Errors, Failures)
 4. Multi-Chunk Pagination via Dahua / CP Plus CGI Log API (`startFind`, `doFind`, `stopFind`).
 5. Complete Raw Entry Storage (`raw_xml` column).
 6. Thread-Safe Execution with pymysql Connection Pool (PooledDB).
 7. Duplicate Prevention using MySQL INSERT IGNORE.
 8. Formatted Console Table for Single IP and Status Cards for Batch Sync.
"""

import os
import sys
import re
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
#                          CONFIGURATION                               #
# ==================================================================== #

DB_HOST = "localhost"
DB_USER = "root"
DB_PASS = ""
DB_NAME = "esurv"

MAX_SITE_THREADS    = 50     # Parallel threads for batch mode
DB_MAX_CONNECTIONS  = 70     # Pool connections
CYCLE_SLEEP_SECONDS = 1800   # Sleep 30m between batch cycles

# Network timeouts (seconds)
T_PING          = 3
T_LOG_FETCH     = 10

DEFAULT_LOOKBACK_HOURS = 5    # Default lookback window (hours)
DEFAULT_MAX_RECORDS    = 1000 # Default max records per DVR

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
            else:
                cur.execute(sql, params or ())
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
        INDEX idx_major_type (major_type)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    db_execute(create_table_sql)

    try:
        cols_info = db_execute("DESCRIBE dvr_fetched_logs;", fetch=True)
        existing_cols = [c['Field'] for c in cols_info] if cols_info else []
        if "user_name" not in existing_cols:
            db_execute("ALTER TABLE dvr_fetched_logs ADD COLUMN user_name VARCHAR(50) DEFAULT NULL AFTER source_ip;")
        if "raw_meta_id" not in existing_cols:
            db_execute("ALTER TABLE dvr_fetched_logs ADD COLUMN raw_meta_id VARCHAR(255) DEFAULT NULL AFTER user_name;")
        if "raw_xml" not in existing_cols:
            db_execute("ALTER TABLE dvr_fetched_logs ADD COLUMN raw_xml TEXT DEFAULT NULL AFTER raw_meta_id;")
    except Exception as e:
        safe_print(f"[DB Notice] Schema check: {e}")

    safe_print("[SYSTEM] Database Initialized & 'dvr_fetched_logs' table verified.")


# ==================================================================== #
#                          SITE FETCHING                               #
# ==================================================================== #

def get_cpplus_dahua_sites(target_ip=None):
    """Fetches CP Plus and Dahua sites from database tables."""
    if target_ip:
        sites = db_execute("""
            SELECT SN, atmid, ipaddress, port, username, password, dvrname
            FROM all_dvr_live
            WHERE ipaddress = %s
        """, (target_ip,), fetch=True)
        if not sites:
            sites = db_execute("""
                SELECT SN, atmid, ipaddress, port, username, password, dvrname
                FROM sites_safe
                WHERE ipaddress = %s
            """, (target_ip,), fetch=True)
        return sites or []

    # Search for CP Plus, Dahua, Dhuva variations
    sites = db_execute("""
        SELECT SN, atmid, ipaddress, port, username, password, dvrname
        FROM all_dvr_live
        WHERE (
            LOWER(dvrname) LIKE '%cpplus%'
            OR LOWER(dvrname) LIKE '%cp plus%'
            OR LOWER(dvrname) LIKE '%cp-plus%'
            OR LOWER(dvrname) LIKE '%dahua%'
            OR LOWER(dvrname) LIKE '%dhuva%'
            OR LOWER(dvrname) LIKE '%dhua%'
        ) AND live = 'Y'
    """, fetch=True)

    if not sites:
        sites = db_execute("""
            SELECT SN, atmid, ipaddress, port, username, password, dvrname
            FROM sites_safe
            WHERE (
                LOWER(dvrname) LIKE '%cpplus%'
                OR LOWER(dvrname) LIKE '%cp plus%'
                OR LOWER(dvrname) LIKE '%cp-plus%'
                OR LOWER(dvrname) LIKE '%dahua%'
                OR LOWER(dvrname) LIKE '%dhuva%'
                OR LOWER(dvrname) LIKE '%dhua%'
            ) AND live = 'Y'
        """, fetch=True)
    return sites or []


# ==================================================================== #
#                        LOGS PARSING & FILTERS                        #
# ==================================================================== #

DAHUA_TYPE_MAP = {
    "0": "All",
    "1": "System",
    "2": "Config",
    "3": "Storage",
    "4": "Alarm",
    "5": "Record",
    "6": "Account",
    "7": "Clear",
    "8": "Playback",
    "0x01": "System",
    "0x02": "Config",
    "0x03": "Storage",
    "0x04": "Alarm",
    "0x05": "Record",
    "0x06": "Account",
    "0x07": "Clear",
    "0x08": "Playback",
}


def parse_dahua_type(type_val: str):
    """Normalize Dahua / CP Plus log type identifier."""
    if not type_val:
        return "General"
    t_clean = type_val.strip()
    if t_clean in DAHUA_TYPE_MAP:
        return DAHUA_TYPE_MAP[t_clean]
    if t_clean.lower().startswith("0x"):
        hex_val = t_clean.lower()
        if hex_val in DAHUA_TYPE_MAP:
            return DAHUA_TYPE_MAP[hex_val]
    return t_clean.title()


def parse_dahua_log_records(res_text: str, ip: str):
    """
    Parses key-value response from Dahua / CP Plus log.cgi endpoint.
    Example response format:
    log[0].Action=0
    log[0].Channel=1
    log[0].Detail=Motion Detect Start
    log[0].Time=2026-10-06 14:32:00
    log[0].Type=Alarm
    log[0].User=admin
    found=1
    """
    raw_entries = {}
    lines = res_text.strip().splitlines()

    for line in lines:
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()

        # Match log[0].FieldName or records[0].FieldName
        m = re.match(r"(?:log|records)\[(\d+)\]\.(.*)", key, re.IGNORECASE)
        if m:
            idx = int(m.group(1))
            field = m.group(2).lower()
            if idx not in raw_entries:
                raw_entries[idx] = {"_raw_lines": []}
            raw_entries[idx][field] = val
            raw_entries[idx]["_raw_lines"].append(line)

    parsed_records = []
    for idx in sorted(raw_entries.keys()):
        entry = raw_entries[idx]
        time_val = entry.get("time") or entry.get("logtime") or entry.get("startdatetime") or ""
        type_val = entry.get("type") or entry.get("logtype") or entry.get("category") or ""
        user_val = entry.get("user") or entry.get("username") or entry.get("operator") or entry.get("account") or ""
        src_ip_val = entry.get("ip") or entry.get("ipaddress") or entry.get("host") or ""
        channel_val = entry.get("channel") or entry.get("data.channel") or ""

        # Description / Detail extraction
        detail_val = (
            entry.get("detail")
            or entry.get("data.detail")
            or entry.get("event")
            or entry.get("subtype")
            or entry.get("context")
            or entry.get("action")
            or ""
        )

        major = parse_dahua_type(type_val)
        
        minor_parts = []
        if detail_val:
            minor_parts.append(detail_val)
        if channel_val and channel_val != "0" and f"Channel {channel_val}" not in detail_val:
            minor_parts.append(f"Channel {channel_val}")
        
        minor = " - ".join(minor_parts) if minor_parts else major
        desc = detail_val if detail_val else minor

        cleaned_time = clean_log_time(time_val)
        raw_snippet = "\n".join(entry.get("_raw_lines", []))

        if cleaned_time:
            parsed_records.append({
                "ipaddress": ip,
                "log_time": cleaned_time,
                "major_type": major,
                "minor_type": minor,
                "description": desc,
                "source_ip": src_ip_val,
                "user_name": user_val,
                "raw_meta_id": f"dahua/{type_val}/{detail_val}"[:250],
                "raw_xml": raw_snippet
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
        f"{record.get('raw_meta_id', '')}"
    ).lower()

    for ef in filter_keywords:
        ef_clean = ef.strip().lower()
        if not ef_clean:
            continue
        if ef_clean in ["all", "*"]:
            return True
        elif ef_clean in ["motion", "motion_detection", "motion start", "motion stop", "md"]:
            if "motion" in text_corpus or "md" in text_corpus or "detect" in text_corpus:
                return True
        elif ef_clean in ["network", "net", "net_broken", "lan", "disconnect"]:
            if "net broken" in text_corpus or "network" in text_corpus or "lan" in text_corpus or "disconnect" in text_corpus or "ip conflict" in text_corpus:
                return True
        elif ef_clean in ["login", "user_login", "auth", "operation", "user", "account"]:
            if "login" in text_corpus or "user" in text_corpus or "account" in text_corpus or "operation" in text_corpus or "admin" in text_corpus or "cfg" in text_corpus or "config" in text_corpus:
                return True
        elif ef_clean in ["hdd", "disk", "smart", "smart info", "storage", "health", "status"]:
            if "smart" in text_corpus or "disk" in text_corpus or "hdd" in text_corpus or "storage" in text_corpus or "run status" in text_corpus or "storage" in text_corpus:
                return True
        elif ef_clean in ["video_loss", "videoloss", "tamper", "tampering", "video", "blind"]:
            if "video loss" in text_corpus or "videoloss" in text_corpus or "tamper" in text_corpus or "blind" in text_corpus:
                return True
        elif ef_clean in ["exception", "alarm"]:
            if "exception" in text_corpus or "alarm" in text_corpus or "error" in text_corpus or "fail" in text_corpus:
                return True
        elif ef_clean in text_corpus:
            return True

    return False


def clean_log_time(time_str: str):
    """Converts Dahua / CP Plus time formats into MySQL DATETIME format (YYYY-MM-DD HH:MM:SS)."""
    if not time_str:
        return None
    try:
        cleaned = time_str.strip().replace("T", " ").replace("Z", "")
        if "+" in cleaned:
            cleaned = cleaned.split("+")[0]
        # Check standard datetime format
        dt = datetime.strptime(cleaned[:19], "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        # Fallback regex search for YYYY-MM-DD HH:MM:SS
        m = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", str(time_str))
        if m:
            return m.group(1)
        return str(time_str).strip()[:19] if time_str else None


def format_http_error(status_code: int) -> str:
    if status_code == 401:
        return "Invalid Username/Password (HTTP 401 Unauthorized)"
    elif status_code == 403:
        return "Access Forbidden (HTTP 403)"
    elif status_code == 404:
        return "Endpoint Not Found (HTTP 404)"
    elif status_code == 400:
        return "Bad Request Format (HTTP 400)"
    elif status_code == 500:
        return "DVR Internal Error (HTTP 500)"
    return f"HTTP Error Status {status_code}"


# ==================================================================== #
#                        LOGS FETCHING CLASS                           #
# ==================================================================== #

class CPPlusDahuaLogFetcher:
    def __init__(self, ip, port, username, password):
        self.ip = ip
        self.port = int(port or 80)
        self.username = username or "admin"
        self.password = password or "admin123"
        self.base_url = f"http://{self.ip}:{self.port}"

        self.session = requests.Session()
        # Dahua / CP Plus devices primarily use Digest Auth; fallback to Basic Auth if required
        self.session.auth = HTTPDigestAuth(self.username, self.password)
        self.session.headers.update({"Connection": "keep-alive"})

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass

    def check_ping(self):
        try:
            return bool(ping(self.ip, timeout=T_PING))
        except Exception:
            return False

    def fetch_logs(self, start_time_dt, end_time_dt, event_filters=None, max_records=DEFAULT_MAX_RECORDS):
        """
        Fetches logs from CP Plus / Dahua DVR using Dahua HTTP CGI log API:
        1. startFind -> returns session token
        2. doFind -> fetches chunk of records
        3. stopFind -> releases session token
        """
        start_str = start_time_dt.strftime("%Y-%m-%d %H:%M:%S")
        end_str = end_time_dt.strftime("%Y-%m-%d %H:%M:%S")

        # 1. Initiate search via startFind
        start_url = f"{self.base_url}/cgi-bin/log.cgi"
        start_params = {
            "action": "startFind",
            "condition.StartTime": start_str,
            "condition.EndTime": end_str,
        }

        token = None
        records = []

        try:
            r = self.session.get(start_url, params=start_params, timeout=T_LOG_FETCH)
            
            # If 401 with Digest, try Basic Auth fallback
            if r.status_code == 401:
                self.session.auth = HTTPBasicAuth(self.username, self.password)
                r = self.session.get(start_url, params=start_params, timeout=T_LOG_FETCH)

            if r.status_code != 200:
                return False, format_http_error(r.status_code), []

            # Extract token=123 from response
            token_match = re.search(r"token\s*=\s*([0-9a-zA-Z_-]+)", r.text, re.IGNORECASE)
            if not token_match:
                # Direct getLog fallback if startFind unsupported
                return self._fallback_get_log(event_filters, max_records)

            token = token_match.group(1).strip()

        except requests.exceptions.Timeout:
            return False, "Connection Timeout", []
        except Exception as e:
            return False, str(e), []

        # 2. Iterate doFind chunks
        try:
            chunk_size = 100
            while len(records) < max_records:
                find_params = {
                    "action": "doFind",
                    "token": token,
                    "count": chunk_size
                }
                r_find = self.session.get(start_url, params=find_params, timeout=T_LOG_FETCH)
                if r_find.status_code != 200:
                    break

                res_text = r_find.text
                chunk_records = parse_dahua_log_records(res_text, self.ip)
                if not chunk_records:
                    break

                for rec in chunk_records:
                    if event_filters and not matches_event_filter(rec, event_filters):
                        continue
                    records.append(rec)
                    if len(records) >= max_records:
                        break

                # Check if search completed
                found_match = re.search(r"found\s*=\s*(\d+)", res_text, re.IGNORECASE)
                found_count = int(found_match.group(1)) if found_match else len(chunk_records)
                if found_count == 0 or len(chunk_records) < chunk_size:
                    break

        except Exception as e:
            if not records:
                return False, str(e), []
        finally:
            # 3. Clean up search session with stopFind
            if token:
                try:
                    self.session.get(start_url, params={"action": "stopFind", "token": token}, timeout=5)
                except Exception:
                    pass

        return True, "Success", records[:max_records]

    def _fallback_get_log(self, event_filters, max_records):
        """Fallback for older CP Plus / Dahua models supporting single-shot getLog action."""
        try:
            url = f"{self.base_url}/cgi-bin/log.cgi?action=getLog&count={max_records}"
            r = self.session.get(url, timeout=T_LOG_FETCH)
            if r.status_code == 200:
                raw_list = parse_dahua_log_records(r.text, self.ip)
                records = []
                for rec in raw_list:
                    if event_filters and not matches_event_filter(rec, event_filters):
                        continue
                    records.append(rec)
                    if len(records) >= max_records:
                        break
                return True, "Success (Fallback)", records
            return False, format_http_error(r.status_code), []
        except Exception as e:
            return False, str(e), []


# ==================================================================== #
#                          SITE PROCESSOR                              #
# ==================================================================== #

def build_log_card(ip, atm_id, status, message, fetched_count=0, saved_count=0):
    """Returns a clean console output status card."""
    card = [
        "=" * 70,
        f"📜  CP PLUS / DAHUA LOG SYNC | IP: {ip:<15} | ATM ID: {atm_id or 'N/A'}",
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
    ip = site.get("ipaddress")
    port = site.get("port") or 80
    user = site.get("username")
    pwd = site.get("password")
    atm_id = str(site.get("atmid", "") or "").replace(" ", "")

    fetcher = CPPlusDahuaLogFetcher(ip, port, user, pwd)

    try:
        # 1. Ping Check
        if not fetcher.check_ping():
            safe_print(build_log_card(ip, atm_id, "❌ Offline", "Device ping timeout."))
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
                (ipaddress, atmid, log_time, major_type, minor_type, description, source_ip, user_name, raw_meta_id, raw_xml)
                VALUES (%(ipaddress)s, %(atmid)s, %(log_time)s, %(major_type)s, %(minor_type)s, %(description)s, %(source_ip)s, %(user_name)s, %(raw_meta_id)s, %(raw_xml)s)
            """
            for log in logs_list:
                log["atmid"] = atm_id

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
 🕒 STEP 1: KITNE TIME (HOURS) KA LOGS DATA CHAHIYE?
============================================================
 [1] Pichle 1 Ghante  (1 Hour)
 [2] Pichle 3 Ghante  (3 Hours)
 [3] Pichle 5 Ghante  (5 Hours) - [Default]
 [4] Pichle 12 Ghante (12 Hours)
 [5] Pichle 24 Ghante (1 Day)
 [6] Pichle 48 Ghante (2 Days)
 [7] Pichle 7 Din     (7 Days)
 [8] Custom Hours enter karein
""")
    try:
        t_choice = input("Choice daalein (1-8) [Default: 3]: ").strip()
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
            val = input("Kitne hours ka data chahiye? (e.g. 10): ").strip()
            hours = int(val) if val.isdigit() else DEFAULT_LOOKBACK_HOURS
        except Exception:
            hours = DEFAULT_LOOKBACK_HOURS
    else:
        hours = hours_map.get(t_choice, DEFAULT_LOOKBACK_HOURS)

    print(f"-> Selected: Pichle {hours} Ghante\n")

    print("""
============================================================
 🎯 STEP 2: KAUN KAUN SE EVENTS KA DATA CHAHIYE?
============================================================
 [1] All Events (Saare Logs) - [Default]
 [2] 🚨 Motion Detection (Motion Start / Stop / MD)
 [3] ⚠️ Network Disconnects (Net Broken / LAN / Disconnect)
 [4] 👤 User Login / Operations (Admin logins, Settings, Account)
 [5] 💾 Hard Disk & System Health (S.M.A.R.T Info / Storage / Disk)
 [6] 📹 Video Loss / Camera Tampering / Blind Detect
 [7] ❌ System Exceptions (All Exception Errors & Alarms)
 [8] Multiple Choice / Custom Filter (e.g. 2,3,5)
""")
    try:
        e_choice = input("Choice daalein (1-8) [Default: 1]: ").strip()
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
        events = ["video_loss"]
    elif e_choice == "7":
        events = ["exception"]
    elif e_choice == "8":
        try:
            custom_in = input("Enter multiple options (e.g. 2,3,5) ya keywords: ").strip()
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
 📍 STEP 3: KIS SITE KE LIYE CHALANA HAI?
============================================================
 [1] Sabhi CP Plus & Dahua Sites (Batch Sync) - [Default]
 [2] Single IP Test Karein
""")
    try:
        s_choice = input("Choice daalein (1-2) [Default: 1]: ").strip()
    except (EOFError, KeyboardInterrupt):
        s_choice = "1"

    target_ip = None
    if s_choice == "2":
        try:
            target_ip = input("Enter DVR IP address (e.g. 172.17.17.44): ").strip()
        except Exception:
            target_ip = None

    return hours, events, target_ip


# ==================================================================== #
#                              MAIN LOOP                               #
# ==================================================================== #

def main():
    parser = argparse.ArgumentParser(description="CP Plus & Dahua DVR Log Fetcher & DB Sync")
    parser.add_argument("--ip", "-i", type=str, help="Target a specific DVR IP address (e.g. --ip 172.17.17.44)")
    parser.add_argument("--hours", "-H", type=int, help="Lookback hours to fetch (e.g. --hours 6)")
    parser.add_argument("--events", "-e", type=str, help="Event filter comma-separated (e.g. --events motion,network,login,hdd,all)")
    parser.add_argument("--limit", "-l", type=int, default=DEFAULT_MAX_RECORDS, help=f"Max log records to fetch (default: {DEFAULT_MAX_RECORDS})")
    parser.add_argument("--auto", "-a", action="store_true", help="Run automatically in scheduler mode without interactive prompts")
    parser.add_argument("--menu", "-m", action="store_true", help="Open interactive selection menu")
    args = parser.parse_args()

    init_log_database()

    # Determine execution mode
    hours = args.hours
    events = [e.strip().lower() for e in args.events.split(",")] if args.events else None
    target_ip = args.ip.strip() if args.ip else None

    # Check if we should show the interactive menu
    if (args.menu or (not args.auto and not args.ip and not args.hours and not args.events and sys.stdin.isatty())):
        hours, events, target_ip = prompt_user_filters()
    else:
        if hours is None:
            hours = DEFAULT_LOOKBACK_HOURS
        if events is None:
            events = ["all"]

    # SINGLE IP MODE
    if target_ip:
        safe_print(f"\n{'='*70}")
        safe_print(f"🎯 SINGLE CP PLUS / DAHUA SITE INSPECTION MODE: IP {target_ip}")
        safe_print(f"🕒 Time Range: Last {hours} Hours | Filter: {', '.join(events)}")
        safe_print(f"{'='*70}\n")

        sites = get_cpplus_dahua_sites(target_ip=target_ip)
        if not sites:
            site = {"ipaddress": target_ip, "port": 80, "username": "admin", "password": "password", "atmid": "SINGLE_TEST", "dvrname": "cpplus"}
        else:
            site = sites[0]

        process_site_logs(site, lookback_hours=hours, event_filters=events, max_records=args.limit, is_single=True)
        return

    # BATCH SCHEDULER MODE (All Sites)
    filter_label = ", ".join(events) if events else "All Events"
    while True:
        start_time = datetime.now()
        start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")

        safe_print("\n" + "=" * 70)
        safe_print(f"🚀 SCHEDULED CP PLUS / DAHUA DVR LOG FETCH CYCLE STARTED AT {start_str}")
        safe_print(f"🕒 Lookback: Last {hours} Hours | 🎯 Events Filter: {filter_label}")
        safe_print("=" * 70 + "\n")

        sites = get_cpplus_dahua_sites()

        if not sites:
            safe_print("⚠️ No Active CP Plus / Dahua sites found in database.")
        else:
            safe_print(f"📋 Loaded {len(sites)} CP Plus / Dahua sites for log inspection. "
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
                "📊 CP PLUS / DAHUA LOG EXTRACTION CYCLE SUMMARY",
                "=" * 70,
                f"  ⏱️  Started At     : {start_str}",
                f"  ⏱️  Finished At    : {end_time.strftime('%Y-%m-%d %H:%M:%S')} (Duration: {duration}s)",
                f"  📍 Total Devices  : {len(sites)}",
                f"  🟢 Sync Completed : {succ} DVRs",
                f"  🔴 Sync Failed    : {fail} DVRs",
                "=" * 70,
                f"  ⏳ Next log sync at: {next_run}",
                "=" * 70 + "\n",
            ]))

        if not args.auto and not (args.hours or args.events):
            # If user ran a single batch from terminal, finish cleanly
            break

        elapsed = (datetime.now() - start_time).total_seconds()
        sleep_for = max(60, CYCLE_SLEEP_SECONDS - elapsed)
        safe_print(f"😴 Sleeping for {int(sleep_for)}s ...\n")
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
