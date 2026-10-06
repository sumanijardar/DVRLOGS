# -*- coding: utf-8 -*-
"""
Hikvision DVR Log Fetcher & DB Sync - Advanced Filter Edition
--------------------------------------------------------------
FEATURES:
 1. Interactive Selection Menu: Choose Time (Hours) & Event Types on the fly!
 2. CLI Flags: `--hours 5`, `--events motion,network`, `--ip 172.17.17.44`, `--limit 1000`, `--auto`.
 3. Fine-Grained Event Filters:
    - 🚨 Motion Detection (Motion Start / Stop)
    - ⚠️ Network Disconnects (Net Broken / LAN)
    - 👤 User Login / Operations (Admin login, Config changes)
    - 💾 Hard Disk & System Health (S.M.A.R.T Info / Run Status)
    - 📹 Video Loss / Camera Tampering
    - ❌ System Exceptions
 4. Multi-Chunk Pagination (fetches 64-item chunks continuously).
 5. Complete Raw XML Storage (`raw_xml` column).
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
import xml.etree.ElementTree as ET

import requests
from requests.auth import HTTPDigestAuth
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
DB_MAX_CONNECTIONS   = 70     # Pool connections
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
    mincached=5,
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
                # Replace unsupported characters with ascii-safe equivalents
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

def get_hikvision_sites(target_ip=None):
    if target_ip:
        sites = db_execute("""
            SELECT SN, atmid, ipaddress, port, username, password
            FROM all_dvr_live
            WHERE ipaddress = %s
        """, (target_ip,), fetch=True)
        if not sites:
            sites = db_execute("""
                SELECT SN, atmid, ipaddress, port, username, password
                FROM sites_safe
                WHERE ipaddress = %s
            """, (target_ip,), fetch=True)
        return sites or []

    sites = db_execute("""
        SELECT SN, atmid, ipaddress, port, username, password
        FROM all_dvr_live
        WHERE dvrname = 'hikvision' AND live = 'Y'
    """, fetch=True)

    if not sites:
        sites = db_execute("""
            SELECT SN, atmid, ipaddress, port, username, password
            FROM sites_safe
            WHERE dvrname = 'hikvision' AND live = 'Y'
        """, fetch=True)
    return sites or []


# ==================================================================== #
#                        LOGS PARSING & FILTERS                        #
# ==================================================================== #

def parse_meta_id(meta_id: str):
    """Extract major category and event title from Hikvision metaId."""
    if not meta_id:
        return "General", "Unknown"

    parts = (
        meta_id.replace("log.hikvision.com/", "")
        .replace("log.std-cgi.com/", "")
        .split("/")
    )

    major = "General"
    event_parts = []

    for idx, p in enumerate(parts):
        if idx == 0:
            major = p.title()
        else:
            clean = re.sub(r"([a-z])([A-Z])", r"\1 \2", p).title()
            if clean.isdigit():
                clean = f"Channel {clean}"
            event_parts.append(clean)

    minor = " - ".join(event_parts) if event_parts else major
    return major, minor


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
        elif ef_clean in ["motion", "motion_detection", "motion start", "motion stop"]:
            if "motion" in text_corpus:
                return True
        elif ef_clean in ["network", "net", "net_broken", "lan", "disconnect"]:
            if "net broken" in text_corpus or "network" in text_corpus or "lan" in text_corpus or "disconnect" in text_corpus:
                return True
        elif ef_clean in ["login", "user_login", "auth", "operation", "user"]:
            if "login" in text_corpus or "user" in text_corpus or "operation" in text_corpus or "remote login" in text_corpus or "cfg" in text_corpus:
                return True
        elif ef_clean in ["hdd", "disk", "smart", "smart info", "storage", "health", "status"]:
            if "smart" in text_corpus or "disk" in text_corpus or "hdd" in text_corpus or "hard disk" in text_corpus or "run status" in text_corpus:
                return True
        elif ef_clean in ["video_loss", "videoloss", "tamper", "tampering", "video"]:
            if "video loss" in text_corpus or "videoloss" in text_corpus or "tamper" in text_corpus:
                return True
        elif ef_clean in ["exception"]:
            if "exception" in text_corpus:
                return True
        elif ef_clean in text_corpus:
            return True

    return False


def clean_iso_time(iso_str):
    """Converts Hikvision ISO time format (e.g. 2026-09-30T14:20:15Z) into MySQL DATETIME format."""
    if not iso_str:
        return None
    try:
        cleaned = iso_str.replace("T", " ").replace("Z", "")
        if "+" in cleaned:
            cleaned = cleaned.split("+")[0]
        return cleaned.strip()
    except Exception:
        return iso_str


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

class HikvisionLogFetcher:
    def __init__(self, ip, port, username, password):
        self.ip = ip
        self.port = int(port or 81)
        self.username = username or "admin"
        self.password = password or "trans@123"
        self.base_url = f"http://{self.ip}:{self.port}"
        
        self.session = requests.Session()
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
        """Calls Hikvision ISAPI logSearch endpoint with auto-fallback and full chunk pagination."""
        url = f"{self.base_url}/ISAPI/ContentMgmt/logSearch"
        headers = {"Content-Type": "application/xml"}

        start_str = start_time_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = end_time_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        records = []
        position = 0
        search_id = str(uuid.uuid4()).upper()

        while len(records) < max_records:
            xml_payload = f"""<?xml version="1.0" encoding="utf-8"?>
<CMSearchDescription>
    <searchID>{search_id}</searchID>
    <metaId>log.hikvision.com</metaId>
    <timeSpanList>
        <timeSpan>
            <startTime>{start_str}</startTime>
            <endTime>{end_str}</endTime>
        </timeSpan>
    </timeSpanList>
    <maxResults>100</maxResults>
    <searchResultPostion>{position}</searchResultPostion>
    <searchResultPosition>{position}</searchResultPosition>
</CMSearchDescription>"""

            res_text = ""
            status_code = 0
            try:
                r = self.session.post(url, data=xml_payload, headers=headers, timeout=T_LOG_FETCH)
                status_code = r.status_code
                res_text = r.text

                # Fallback to log.std-cgi.com if log.hikvision.com returns non-200 or NO MATCHES on first attempt
                if (status_code != 200 and status_code != 401) or ("<numOfMatches>0</numOfMatches>" in res_text and position == 0):
                    xml_payload_alt = xml_payload.replace("log.hikvision.com", "log.std-cgi.com")
                    r_alt = self.session.post(url, data=xml_payload_alt, headers=headers, timeout=T_LOG_FETCH)
                    if r_alt.status_code == 200:
                        status_code = r_alt.status_code
                        res_text = r_alt.text

                if status_code != 200 or "<responseStatus>true</responseStatus>" not in res_text:
                    if not records:
                        return False, format_http_error(status_code), []
                    break

            except requests.exceptions.Timeout:
                if not records:
                    return False, "Connection Timeout", []
                break
            except Exception as e:
                if not records:
                    return False, str(e), []
                break

            # Parse logDescriptor entries from XML
            match_items = re.findall(r"<logDescriptor\b[^>]*>(.*?)</logDescriptor>", res_text, re.DOTALL)
            if not match_items:
                break

            for item in match_items:
                meta = re.search(r"<metaId>(.*?)</metaId>", item)
                time_m = re.search(r"<(?:StartDateTime|time)>(.*?)</(?:StartDateTime|time)>", item)
                user_m = re.search(r"<(?:userName|panelUser)>(.*?)</(?:userName|panelUser)>", item)
                ip_m = re.search(r"<ipAddress>(.*?)</ipAddress>", item)
                info_m = re.search(r"<(?:additionInformation|extraInfo)>(.*?)</(?:additionInformation|extraInfo)>", item, re.DOTALL)

                meta_val = meta.group(1).strip() if meta else ""
                time_val = time_m.group(1).strip() if time_m else ""
                user_val = user_m.group(1).strip() if user_m else ""
                src_ip_val = ip_m.group(1).strip() if ip_m else ""
                desc_val = info_m.group(1).strip().replace("\n", " | ") if info_m else ""

                major, minor = parse_meta_id(meta_val)
                parsed_time = clean_iso_time(time_val)
                raw_xml_snippet = f"<logDescriptor>{item.strip()}</logDescriptor>"

                if parsed_time:
                    rec = {
                        "ipaddress": self.ip,
                        "log_time": parsed_time,
                        "major_type": major,
                        "minor_type": minor,
                        "description": desc_val if desc_val else minor,
                        "source_ip": src_ip_val,
                        "user_name": user_val,
                        "raw_meta_id": meta_val,
                        "raw_xml": raw_xml_snippet
                    }

                    # Filter evaluation
                    if event_filters and not matches_event_filter(rec, event_filters):
                        continue

                    records.append(rec)
                    if len(records) >= max_records:
                        break

            # Advance pagination position if DVR signals MORE records
            more_flag = re.search(r"<responseStatusStrg>(.*?)</responseStatusStrg>", res_text)
            is_more = more_flag and more_flag.group(1).strip().upper() == "MORE"
            if is_more and len(match_items) > 0:
                position += len(match_items)
            else:
                break

        return True, "Success", records[:max_records]


# ==================================================================== #
#                          SITE PROCESSOR                              #
# ==================================================================== #

def build_log_card(ip, atm_id, status, message, fetched_count=0, saved_count=0):
    """Returns a clean console output status card."""
    card = [
        "=" * 70,
        f"📜  HIKVISION LOG SYNC | IP: {ip:<15} | ATM ID: {atm_id or 'N/A'}",
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
    port = site.get("port") or 81
    user = site.get("username")
    pwd = site.get("password")
    atm_id = str(site.get("atmid", "") or "").replace(" ", "")

    fetcher = HikvisionLogFetcher(ip, port, user, pwd)
    
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
 [2] 🚨 Motion Detection (Motion Start / Stop)
 [3] ⚠️ Network Disconnects (Net Broken / LAN)
 [4] 👤 User Login / Operations (Admin logins, Settings)
 [5] 💾 Hard Disk & System Health (S.M.A.R.T Info / Run Status)
 [6] 📹 Video Loss / Camera Tampering
 [7] ❌ System Exceptions (All Exception Errors)
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
 [1] Sabhi 723 Sites (Batch Sync) - [Default]
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
    parser = argparse.ArgumentParser(description="Hikvision DVR Log Fetcher & DB Sync")
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
        safe_print(f"🎯 SINGLE SITE INSPECTION MODE: IP {target_ip}")
        safe_print(f"🕒 Time Range: Last {hours} Hours | Filter: {', '.join(events)}")
        safe_print(f"{'='*70}\n")

        sites = get_hikvision_sites(target_ip=target_ip)
        if not sites:
            site = {"ipaddress": target_ip, "port": 81, "username": "admin", "password": "password", "atmid": "SINGLE_TEST"}
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
        safe_print(f"🚀 SCHEDULED HIKVISION DVR LOG FETCH CYCLE STARTED AT {start_str}")
        safe_print(f"🕒 Lookback: Last {hours} Hours | 🎯 Events Filter: {filter_label}")
        safe_print("=" * 70 + "\n")

        sites = get_hikvision_sites()

        if not sites:
            safe_print("⚠️ No Active Hikvision sites found in database.")
        else:
            safe_print(f"📋 Loaded {len(sites)} sites for log inspection. "
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
                "📊 LOG EXTRACTION CYCLE SUMMARY",
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
