from __future__ import annotations

import csv
import json
import re
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# 时区常量
# ---------------------------------------------------------------------------
UTC = timezone.utc
CST = timezone(timedelta(hours=8), name="CST")  # China Standard Time (UTC+8)

# Windows FILETIME epoch: 1601-01-01 00:00:00 UTC
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_FILETIME_TICKS_PER_SEC = 10_000_000  # 100-nanosecond intervals

# Unix epoch
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


# ---------------------------------------------------------------------------
# 时间戳解码函数 — DCode 风格的多格式时间戳转换
# ---------------------------------------------------------------------------

def decode_windows_filetime(value: int, *, tz: timezone = UTC) -> datetime | None:
    """将 64-bit Windows FILETIME（100ns ticks since 1601-01-01 UTC）解码为 datetime。"""
    if value <= 0 or value > 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
        return dt.astimezone(tz)
    except (OverflowError, OSError, ValueError):
        return None


def decode_unix_timestamp(value: int | float, *, tz: timezone = UTC) -> datetime | None:
    """将 Unix 时间戳（秒或毫秒）解码为 datetime。"""
    if value < 0:
        return None
    try:
        # 自动检测：毫秒 vs 秒（如果值 > 1e12 认为是毫秒）
        if value > 1e12:
            value = value / 1000.0
        dt = _UNIX_EPOCH + timedelta(seconds=float(value))
        return dt.astimezone(tz)
    except (OverflowError, OSError, ValueError):
        return None


def decode_fat_timestamp(value: int, *, tz: timezone = UTC) -> datetime | None:
    """将 32-bit FAT 时间戳（16-bit date + 16-bit time）解码为 datetime。
    
    FAT date (bits): YYYYYYYMMMMDDDDD  (year since 1980, month, day)
    FAT time (bits): HHHHHMMMMMMSSSS S (hour, minute, seconds/2)
    """
    if value <= 0 or value > 0xFFFFFFFF:
        return None
    try:
        time_part = value & 0xFFFF
        date_part = (value >> 16) & 0xFFFF

        day = date_part & 0x1F
        month = (date_part >> 5) & 0x0F
        year = ((date_part >> 9) & 0x7F) + 1980

        second = (time_part & 0x1F) * 2
        minute = (time_part >> 5) & 0x3F
        hour = (time_part >> 11) & 0x1F

        if not (1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60 and second < 60):
            return None
        dt = datetime(year, month, day, hour, minute, second, tzinfo=tz)
        return dt
    except (ValueError, OverflowError):
        return None


def decode_filetime_bytes(data: bytes, *, tz: timezone = UTC) -> datetime | None:
    """从 8 字节（little-endian）解码 Windows FILETIME。"""
    if len(data) < 8:
        return None
    value = struct.unpack_from("<Q", data)[0]
    return decode_windows_filetime(value, tz=tz)


def decode_fat_timestamp_bytes(data: bytes, *, tz: timezone = UTC) -> datetime | None:
    """从 4 字节（little-endian: 2B time + 2B date）解码 FAT 时间戳。"""
    if len(data) < 4:
        return None
    time_val, date_val = struct.unpack_from("<HH", data)
    combined = (date_val << 16) | time_val
    return decode_fat_timestamp(combined, tz=tz)


def auto_decode_timestamp(value: int | str, *, tz: timezone = UTC) -> list[dict[str, Any]]:
    """DCode 风格：自动尝试多种时间戳格式解码，返回所有合理的解码结果。"""
    results: list[dict[str, Any]] = []
    
    if isinstance(value, str):
        value = value.strip()
        # 尝试解析十六进制
        if value.lower().startswith("0x"):
            try:
                value = int(value, 16)
            except ValueError:
                return results
        else:
            try:
                value = int(value)
            except ValueError:
                try:
                    value = float(value)
                except ValueError:
                    return results
    
    int_value = int(value) if isinstance(value, (int, float)) else 0
    
    # 1. Windows FILETIME (64-bit)
    dt = decode_windows_filetime(int_value, tz=tz)
    if dt and datetime(1970, 1, 1, tzinfo=UTC) < dt < datetime(2100, 1, 1, tzinfo=UTC):
        results.append({
            "format": "Windows FILETIME (64-bit, 100ns since 1601-01-01 UTC)",
            "decoded_utc": dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "decoded_cst": dt.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S CST"),
            "decoded_iso": dt.isoformat(),
        })
    
    # 2. Unix timestamp (seconds)
    dt = decode_unix_timestamp(float(value) if isinstance(value, float) else int_value, tz=tz)
    if dt and datetime(1970, 1, 1, tzinfo=UTC) < dt < datetime(2100, 1, 1, tzinfo=UTC):
        results.append({
            "format": "Unix Timestamp (seconds since 1970-01-01 UTC)" if int_value < 1e12 else "Unix Timestamp (milliseconds since 1970-01-01 UTC)",
            "decoded_utc": dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "decoded_cst": dt.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S CST"),
            "decoded_iso": dt.isoformat(),
        })
    
    # 3. FAT timestamp (32-bit)
    if 0 < int_value <= 0xFFFFFFFF:
        dt = decode_fat_timestamp(int_value, tz=tz)
        if dt and datetime(1980, 1, 1, tzinfo=UTC) < dt.replace(tzinfo=UTC) < datetime(2100, 1, 1, tzinfo=UTC):
            results.append({
                "format": "FAT32 Timestamp (32-bit, 2-sec resolution)",
                "decoded_utc": dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC") if dt.tzinfo else dt.strftime("%Y-%m-%d %H:%M:%S (local)"),
                "decoded_cst": dt.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S CST") if dt.tzinfo else "N/A",
                "decoded_iso": dt.isoformat(),
                "note": "FAT timestamps are typically stored in local time, not UTC.",
            })
    
    # 4. WebKit/Chrome timestamp (microseconds since 1601-01-01 UTC, same epoch as FILETIME)
    if int_value > 1e16:
        try:
            dt_webkit = _FILETIME_EPOCH + timedelta(microseconds=int_value)
            if datetime(1970, 1, 1, tzinfo=UTC) < dt_webkit < datetime(2100, 1, 1, tzinfo=UTC):
                results.append({
                    "format": "WebKit/Chrome Timestamp (microseconds since 1601-01-01 UTC)",
                    "decoded_utc": dt_webkit.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "decoded_cst": dt_webkit.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S CST"),
                    "decoded_iso": dt_webkit.isoformat(),
                })
        except (OverflowError, OSError, ValueError):
            pass
    
    return results


def convert_timezone(
    dt_str: str,
    *,
    from_tz: timezone | None = None,
    to_tz: timezone = CST,
) -> dict[str, str]:
    """将人类可读的时间字符串在时区之间转换。"""
    # 尝试多种常见格式
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M",
    ]
    parsed: datetime | None = None
    for fmt in formats:
        try:
            parsed = datetime.strptime(dt_str.strip(), fmt)
            break
        except ValueError:
            continue
    if parsed is None:
        return {"error": f"Cannot parse datetime string: {dt_str}"}
    
    if from_tz is not None:
        parsed = parsed.replace(tzinfo=from_tz)
    elif parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    
    converted = parsed.astimezone(to_tz)
    return {
        "input": dt_str,
        "from_tz": str(from_tz or UTC),
        "to_tz": str(to_tz),
        "result": converted.strftime("%Y-%m-%d %H:%M:%S"),
        "result_iso": converted.isoformat(),
    }


def analyze_file_timestamps(
    created: datetime | str | None,
    modified: datetime | str | None,
    accessed: datetime | str | None,
) -> dict[str, Any]:
    """分析文件的 CMA（Created/Modified/Accessed）三时间，检测异常。"""
    def _parse(v: datetime | str | None) -> datetime | None:
        if v is None:
            return None
        if isinstance(v, datetime):
            return v
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(str(v).strip(), fmt)
            except ValueError:
                continue
        return None
    
    c = _parse(created)
    m = _parse(modified)
    a = _parse(accessed)
    
    anomalies: list[str] = []
    analysis: dict[str, Any] = {
        "created": c.isoformat() if c else None,
        "modified": m.isoformat() if m else None,
        "accessed": a.isoformat() if a else None,
    }
    
    if c and m:
        if m < c:
            anomalies.append("Modified < Created: 文件可能被复制/移动（Created 反映复制时间，Modified 保留原始修改时间）")
        if m == c:
            anomalies.append("Modified == Created: 文件可能自创建后从未修改")
    
    if c and a:
        if a < c:
            anomalies.append("Accessed < Created: 时间戳可能被篡改或系统时钟曾发生变化")
    
    if c and m and a:
        if c == m == a:
            anomalies.append("C == M == A: 三时间相同，文件可能是批量生成/解压而来")
        earliest = min(c, m, a)
        latest = max(c, m, a)
        if (latest - earliest).days > 365 * 5:
            anomalies.append(f"时间跨度超过5年（{earliest.isoformat()} → {latest.isoformat()}），需确认是否合理")
    
    # NTFS vs FAT32 特征检测
    if c and c.microsecond % 1000000 == 0 and (not m or m.second % 2 == 0):
        anomalies.append("秒数精度为偶数（2秒粒度），可能来自 FAT32 文件系统")
    
    analysis["anomalies"] = anomalies
    analysis["anomaly_count"] = len(anomalies)
    return analysis

TIMESTAMP_RE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s{2}(?P<msg>.*)$"
)
SNAPSHOT_ZH_RE = re.compile(
    r"磁盘快照后共有\s*(?P<total>[\d,]+)\s*个数据项\s*"
    r"\(之前\s*(?P<before>[\d,]+)\s*个,\s*之后\s*\+?(?P<delta>[\d,]+)\s*个\)"
    r".*?处理时间\s*(?P<duration>[0-9:]+)\s*min"
)
ENCRYPTED_HINT_RE = re.compile(r"encrypted|加密", re.IGNORECASE)
SEARCH_HINT_RE = re.compile(r"search|keyword|hit|命中|关键词", re.IGNORECASE)
INVALID_FILENAME_CHARS_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
LIKELY_NAME_RE = re.compile(r"[A-Za-z0-9\u4e00-\u9fff]")

ENCRYPTED_EXTENSIONS = {
    ".aes",
    ".age",
    ".asc",
    ".ccrypt",
    ".crypt",
    ".enc",
    ".gpg",
    ".hc",
    ".jks",
    ".kdb",
    ".kdbx",
    ".key",
    ".keychain",
    ".p12",
    ".pfx",
    ".pgp",
    ".ppk",
    ".tc",
    ".wallet",
}
ENCRYPTED_KEYWORDS = (
    "bitlocker",
    "crypt",
    "encrypt",
    "gpg",
    "keyfile",
    "locker",
    "secret",
    "vault",
    "veracrypt",
)


# ---------------------------------------------------------------------------
# Windows Timeline — ActivitiesCache.db 解析
# ---------------------------------------------------------------------------

# ActivitiesCache.db 中的时间戳是 Unix epoch (seconds)
# ActivityType 常量定义
ACTIVITY_TYPE_MAP: dict[int, str] = {
    5: "App/URI Open",
    6: "App/URI in Use",
    10: "User Notification",
    16: "Copy/Paste (Clipboard)",
}


def parse_activities_cache_db(db_path: Path, *, limit: int = 5000) -> list[dict[str, Any]]:
    """解析 Windows Timeline ActivitiesCache.db (SQLite)，返回活动记录列表。"""
    if not db_path.is_file():
        return []
    records: list[dict[str, Any]] = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # 检查表是否存在
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('Activity', 'ActivityOperation')"
        )
        tables = {row["name"] for row in cursor.fetchall()}

        if "Activity" in tables:
            # 获取列名以适配不同 Windows 版本
            cursor.execute("PRAGMA table_info(Activity)")
            columns = {row["name"] for row in cursor.fetchall()}

            # 构建查询 — 兼容 Win10 1803+ 和更新版本
            select_cols = []
            col_mapping = [
                ("Id", "id"),
                ("AppId", "app_id"),
                ("ActivityType", "activity_type"),
                ("ActivityStatus", "activity_status"),
                ("StartTime", "start_time"),
                ("EndTime", "end_time"),
                ("LastModifiedTime", "last_modified_time"),
                ("ExpirationTime", "expiration_time"),
                ("CreatedInCloud", "created_in_cloud"),
                ("LastModifiedOnClient", "last_modified_on_client"),
                ("OriginalLastModifiedOnClient", "original_last_modified_on_client"),
                ("Payload", "payload"),
                ("Priority", "priority"),
                ("IsLocalOnly", "is_local_only"),
                ("Tag", "tag"),
                ("Group", "group_name"),
                ("MatchId", "match_id"),
                ("PlatformDeviceId", "platform_device_id"),
                ("PackageIdHash", "package_id_hash"),
                ("ETag", "etag"),
            ]
            available_cols = []
            for db_col, alias in col_mapping:
                if db_col in columns:
                    available_cols.append((db_col, alias))
                    select_cols.append(f'"{db_col}" AS "{alias}"')

            if select_cols:
                query = f"SELECT {', '.join(select_cols)} FROM Activity ORDER BY StartTime DESC LIMIT ?"
                cursor.execute(query, (limit,))
                for row in cursor.fetchall():
                    record: dict[str, Any] = {}
                    for db_col, alias in available_cols:
                        val = row[alias]
                        if val is not None:
                            record[alias] = val
                    # 解码 ActivityType
                    if "activity_type" in record:
                        atype = record["activity_type"]
                        record["activity_type_label"] = ACTIVITY_TYPE_MAP.get(atype, f"Unknown({atype})")
                    # 解码 AppId (JSON string)
                    if "app_id" in record and isinstance(record["app_id"], str):
                        try:
                            app_info = json.loads(record["app_id"])
                            if isinstance(app_info, list) and app_info:
                                # 提取 application 名称
                                for entry in app_info:
                                    if isinstance(entry, dict):
                                        platform = entry.get("platform", "")
                                        app = entry.get("application", "")
                                        if app:
                                            record["app_name"] = app
                                            record["app_platform"] = platform
                                            break
                        except (json.JSONDecodeError, TypeError):
                            pass
                    # 解码 Payload (JSON)
                    if "payload" in record and isinstance(record["payload"], str):
                        try:
                            payload = json.loads(record["payload"])
                            if isinstance(payload, dict):
                                for pk in ("displayText", "description", "appDisplayName",
                                           "contentUri", "activationUri"):
                                    if pk in payload:
                                        record[f"payload_{pk}"] = payload[pk]
                        except (json.JSONDecodeError, TypeError):
                            pass
                    # 时间戳转为可读格式
                    for time_key in ("start_time", "end_time", "last_modified_time",
                                     "expiration_time", "last_modified_on_client",
                                     "original_last_modified_on_client", "created_in_cloud"):
                        if time_key in record:
                            ts = record[time_key]
                            if isinstance(ts, (int, float)) and ts > 0:
                                dt = decode_unix_timestamp(ts)
                                if dt:
                                    record[f"{time_key}_utc"] = dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
                                    record[f"{time_key}_cst"] = dt.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S CST")
                    records.append(record)

        conn.close()
    except (sqlite3.Error, OSError) as exc:
        records.append({"_error": f"Failed to parse ActivitiesCache.db: {exc}"})
    return records


# ---------------------------------------------------------------------------
# $I file parser (Windows Recycle Bin metadata)
# ---------------------------------------------------------------------------
def parse_recycle_bin_i_file(i_file_path: Path) -> dict[str, Any] | None:
    """解析 $Recycle.Bin 中的 $I 文件，提取删除时间和原始路径。

    $I 文件格式 (Vista/Win7/8):
      Offset 0: Header/Version (8 bytes, LE uint64) — 1=Vista/7, 2=Win10+
      Offset 8: Original file size (8 bytes, LE uint64)
      Offset 16: Deletion timestamp (8 bytes, FILETIME)
      Offset 24: Original file path (UTF-16LE, fixed 520B for v1, variable for v2)

    $I 文件格式 (Win10+ v2):
      Offset 0: Version (8 bytes) = 2
      Offset 8: Original file size (8 bytes)
      Offset 16: Deletion timestamp (8 bytes, FILETIME)
      Offset 24: Path length (4 bytes, LE uint32, char count including null)
      Offset 28: Original file path (UTF-16LE, variable length)
    """
    try:
        data = i_file_path.read_bytes()
        if len(data) < 28:
            return None
        version = struct.unpack_from("<Q", data, 0)[0]
        file_size = struct.unpack_from("<Q", data, 8)[0]
        ft_raw = struct.unpack_from("<Q", data, 16)[0]
        delete_time = decode_windows_filetime(ft_raw)

        if version == 2 and len(data) >= 32:
            # Win10+ v2 format
            path_char_count = struct.unpack_from("<I", data, 24)[0]
            path_bytes = data[28:28 + path_char_count * 2]
            original_path = path_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
        elif version == 1:
            # Vista/7 format — fixed 520 bytes for path
            path_bytes = data[24:24 + 520]
            original_path = path_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
        else:
            # Unknown version, best-effort
            path_bytes = data[24:]
            original_path = path_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")

        return {
            "i_file": i_file_path.name,
            "version": version,
            "original_file_size": file_size,
            "delete_time_utc": delete_time.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC") if delete_time else None,
            "delete_time_cst": delete_time.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S CST") if delete_time else None,
            "original_path": original_path,
            "original_filename": original_path.rsplit("\\", 1)[-1] if original_path else None,
        }
    except (OSError, struct.error):
        return None


# ---------------------------------------------------------------------------
# LNK Shell Link (.lnk) binary parser
# ---------------------------------------------------------------------------
_LNK_MAGIC = 0x0000004C
_LNK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

# LinkFlags bit masks
_HAS_LINK_TARGET_ID_LIST = 0x00000001
_HAS_LINK_INFO = 0x00000002
_HAS_NAME = 0x00000004
_HAS_RELATIVE_PATH = 0x00000008
_HAS_WORKING_DIR = 0x00000010
_HAS_ARGUMENTS = 0x00000020
_IS_UNICODE = 0x00000080


def _read_lnk_string(data: bytes, offset: int, is_unicode: bool) -> tuple[str, int]:
    """Read a StringData structure from LNK. Returns (string, new_offset)."""
    if offset + 2 > len(data):
        return ("", offset)
    char_count = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if is_unicode:
        byte_len = char_count * 2
        if offset + byte_len > len(data):
            return ("", offset)
        s = data[offset:offset + byte_len].decode("utf-16-le", errors="replace")
        return (s, offset + byte_len)
    else:
        if offset + char_count > len(data):
            return ("", offset)
        s = data[offset:offset + char_count].decode("cp1252", errors="replace")
        return (s, offset + char_count)


def parse_lnk_file(lnk_path: Path) -> dict[str, Any] | None:
    """解析 Windows .lnk 快捷方式文件，提取目标路径、MAC时间、卷序列号等。

    LNK Shell Link Binary Format (MS-SHLLINK):
      Header (76 bytes):
        0x00: Magic (4B) = 0x4C
        0x04: CLSID (16B)
        0x14: LinkFlags (4B)
        0x18: FileAttributes (4B)
        0x1C: CreationTime (8B FILETIME)
        0x24: AccessTime (8B FILETIME)
        0x2C: WriteTime (8B FILETIME)
        0x34: FileSize (4B)
      Then optional: LinkTargetIDList, LinkInfo (contains volume serial + local base path),
      StringData (name, relative path, working dir, arguments).
    """
    try:
        data = lnk_path.read_bytes()
        if len(data) < 76:
            return None

        magic = struct.unpack_from("<I", data, 0)[0]
        if magic != _LNK_MAGIC:
            return None

        clsid = data[4:20]
        if clsid != _LNK_CLSID:
            return None

        link_flags = struct.unpack_from("<I", data, 0x14)[0]
        file_attrs = struct.unpack_from("<I", data, 0x18)[0]

        # MAC timestamps
        ct_raw = struct.unpack_from("<Q", data, 0x1C)[0]
        at_raw = struct.unpack_from("<Q", data, 0x24)[0]
        wt_raw = struct.unpack_from("<Q", data, 0x2C)[0]

        creation_time = decode_windows_filetime(ct_raw)
        access_time = decode_windows_filetime(at_raw)
        write_time = decode_windows_filetime(wt_raw)

        target_size = struct.unpack_from("<I", data, 0x34)[0]

        result: dict[str, Any] = {
            "lnk_file": lnk_path.name,
            "target_file_size": target_size,
            "creation_time_utc": creation_time.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC") if creation_time else None,
            "creation_time_cst": creation_time.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S CST") if creation_time else None,
            "access_time_utc": access_time.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC") if access_time else None,
            "access_time_cst": access_time.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S CST") if access_time else None,
            "write_time_utc": write_time.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC") if write_time else None,
            "write_time_cst": write_time.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S CST") if write_time else None,
            "file_attributes": file_attrs,
        }

        offset = 76  # after header

        # --- LinkTargetIDList ---
        if link_flags & _HAS_LINK_TARGET_ID_LIST:
            if offset + 2 <= len(data):
                id_list_size = struct.unpack_from("<H", data, offset)[0]
                offset += 2 + id_list_size

        # --- LinkInfo ---
        volume_serial = None
        local_base_path = None
        if link_flags & _HAS_LINK_INFO:
            if offset + 4 <= len(data):
                link_info_size = struct.unpack_from("<I", data, offset)[0]
                li_start = offset
                if link_info_size >= 28 and li_start + link_info_size <= len(data):
                    li_header_size = struct.unpack_from("<I", data, li_start + 4)[0]
                    li_flags = struct.unpack_from("<I", data, li_start + 8)[0]
                    vol_id_offset = struct.unpack_from("<I", data, li_start + 12)[0]
                    local_base_path_offset = struct.unpack_from("<I", data, li_start + 16)[0]

                    # VolumeID — extract serial number
                    if li_flags & 0x01 and vol_id_offset > 0:
                        vid_abs = li_start + vol_id_offset
                        if vid_abs + 16 <= len(data):
                            vol_id_size = struct.unpack_from("<I", data, vid_abs)[0]
                            if vol_id_size >= 16:
                                volume_serial = struct.unpack_from("<I", data, vid_abs + 8)[0]

                    # LocalBasePath
                    if li_flags & 0x01 and local_base_path_offset > 0:
                        lbp_abs = li_start + local_base_path_offset
                        if lbp_abs < li_start + link_info_size:
                            end = data.index(b"\x00", lbp_abs) if b"\x00" in data[lbp_abs:li_start + link_info_size] else li_start + link_info_size
                            local_base_path = data[lbp_abs:end].decode("cp1252", errors="replace")

                    # Check for Unicode local base path (header size > 28)
                    if li_header_size >= 36:
                        try:
                            ulbp_offset = struct.unpack_from("<I", data, li_start + 28)[0]
                            if ulbp_offset > 0:
                                ulbp_abs = li_start + ulbp_offset
                                if ulbp_abs < li_start + link_info_size:
                                    # Find null terminator (UTF-16LE)
                                    end = ulbp_abs
                                    while end + 1 < li_start + link_info_size:
                                        if data[end:end + 2] == b"\x00\x00":
                                            break
                                        end += 2
                                    unicode_path = data[ulbp_abs:end].decode("utf-16-le", errors="replace")
                                    if unicode_path:
                                        local_base_path = unicode_path
                        except (struct.error, ValueError):
                            pass

                offset = li_start + link_info_size

        result["volume_serial"] = f"{volume_serial:08X}" if volume_serial else None
        result["local_base_path"] = local_base_path

        # --- StringData ---
        is_unicode = bool(link_flags & _IS_UNICODE)
        for flag, key in (
            (_HAS_NAME, "description"),
            (_HAS_RELATIVE_PATH, "relative_path"),
            (_HAS_WORKING_DIR, "working_dir"),
            (_HAS_ARGUMENTS, "arguments"),
        ):
            if link_flags & flag:
                s, offset = _read_lnk_string(data, offset, is_unicode)
                result[key] = s
            else:
                result[key] = None

        # Derive target path (prefer local_base_path, fallback to relative_path)
        result["target_path"] = local_base_path or result.get("relative_path")

        return result

    except (OSError, struct.error, ValueError):
        return None


# ---------------------------------------------------------------------------
# JumpList parser (AutomaticDestinations / CustomDestinations)
# ---------------------------------------------------------------------------

def parse_automatic_destinations(file_path: Path) -> list[dict[str, Any]]:
    """解析 AutomaticDestinations-ms 文件 (OLE Compound Document)。

    每个 numbered stream 是一个完整的 LNK 文件。
    文件名格式: {AppID}.automaticDestinations-ms
    位置: %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\
    """
    results: list[dict[str, Any]] = []
    try:
        import olefile
        if not olefile.isOleFile(str(file_path)):
            return results
        ole = olefile.OleFileIO(str(file_path))
        # AppID from filename
        app_id = file_path.stem.split(".")[0] if "." in file_path.stem else file_path.stem
        for stream_name in ole.listdir():
            name = "/".join(stream_name)
            # Skip DestList stream (metadata, not LNK)
            if name.lower() == "destlist":
                continue
            try:
                stream_data = ole.openstream(stream_name).read()
                if len(stream_data) < 76:
                    continue
                # Check LNK magic
                magic = struct.unpack_from("<I", stream_data, 0)[0]
                if magic != 0x4C:
                    continue
                # Write to temp and parse with existing LNK parser
                import tempfile, os
                tmp = Path(tempfile.mktemp(suffix=".lnk"))
                tmp.write_bytes(stream_data)
                parsed = parse_lnk_file(tmp)
                os.unlink(tmp)
                if parsed:
                    parsed["jumplist_type"] = "AutomaticDestinations"
                    parsed["app_id"] = app_id
                    parsed["stream_name"] = name
                    parsed["source_file"] = file_path.name
                    results.append(parsed)
            except Exception:
                continue
        ole.close()
    except Exception:
        pass
    return results


def parse_custom_destinations(file_path: Path) -> list[dict[str, Any]]:
    """解析 CustomDestinations-ms 文件 (多个 LNK 文件拼接)。

    文件由多个 LNK 按 magic 0x0000004C 分隔拼接。
    文件名格式: {AppID}.customDestinations-ms
    位置: %APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\
    """
    results: list[dict[str, Any]] = []
    try:
        data = file_path.read_bytes()
        app_id = file_path.stem.split(".")[0] if "." in file_path.stem else file_path.stem
        # Find all LNK magic offsets
        lnk_magic = b"\x4c\x00\x00\x00"
        lnk_clsid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
        offsets: list[int] = []
        pos = 0
        while pos < len(data) - 20:
            idx = data.find(lnk_magic, pos)
            if idx < 0:
                break
            # Verify CLSID follows
            if idx + 20 <= len(data) and data[idx + 4:idx + 20] == lnk_clsid:
                offsets.append(idx)
                pos = idx + 76
            else:
                pos = idx + 1

        for i, start in enumerate(offsets):
            end = offsets[i + 1] if i + 1 < len(offsets) else len(data)
            lnk_data = data[start:end]
            if len(lnk_data) < 76:
                continue
            import tempfile, os
            tmp = Path(tempfile.mktemp(suffix=".lnk"))
            tmp.write_bytes(lnk_data)
            parsed = parse_lnk_file(tmp)
            os.unlink(tmp)
            if parsed:
                parsed["jumplist_type"] = "CustomDestinations"
                parsed["app_id"] = app_id
                parsed["entry_index"] = i
                parsed["source_file"] = file_path.name
                results.append(parsed)
    except Exception:
        pass
    return results


EXPORT_PATTERNS = {
    "search_hits": ["search-hits*", "search_hits*", "keyword-hits*", "keyword_hits*"],
    "encrypted_files": [
        "encrypted-files*",
        "encrypted_files*",
        "encrypted-candidates*",
        "encrypted_candidates*",
    ],
    "snapshot": ["volume-snapshot*", "volume_snapshot*", "disk-snapshot*", "snapshot*"],
    "registry_system": [
        "registry-system*",
        "registry_system*",
        "reg-report-system*",
        "reg_report_system*",
        "system-registry*",
    ],
    "event_logs_system": [
        "event-logs-system*",
        "event_logs_system*",
        "system-events*",
        "system_event*",
        "system-evtx*",
        "evtx-system*",
    ],
    "installed_software": [
        "installed-software*",
        "installed_software*",
        "reg-report-software*",
        "reg_report_software*",
        "registry-software*",
        "registry_software*",
        "software-inventory*",
    ],
    "registry_devices": [
        "registry-devices*",
        "registry_devices*",
        "reg-report-devices*",
        "reg_report_devices*",
        "usbstor*",
        "mounted-devices*",
        "mounted_devices*",
        "device-history*",
    ],
    "sunlogin_logs": [
        "sunlogin-logs*",
        "sunlogin_logs*",
        "sunlogin-log*",
        "sunlogin_log*",
        "sunlogin*",
        "\u5411\u65e5\u8475*",
    ],
    "event_logs_security": [
        "event-logs-security*",
        "event_logs_security*",
        "security-events*",
        "security_event*",
        "security-evtx*",
        "evtx-security*",
    ],
    "event_logs_application": [
        "event-logs-application*",
        "event_logs_application*",
        "application-events*",
        "application_event*",
        "application-evtx*",
        "evtx-application*",
    ],
    "event_logs_terminal_services": [
        "event-logs-terminal*",
        "event_logs_terminal*",
        "terminal-services*",
        "terminal_services*",
        "rdp-events*",
        "rdp_events*",
        "LocalSessionManager*",
        "RemoteConnectionManager*",
        "TerminalServices*",
    ],
    "event_logs_pnp": [
        "event-logs-pnp*",
        "event_logs_pnp*",
        "pnp-events*",
        "pnp_events*",
        "kernel-pnp*",
        "kernel_pnp*",
        "userpnp*",
        "plug-and-play*",
        "plug_and_play*",
    ],
    "event_logs_wlan": [
        "event-logs-wlan*",
        "event_logs_wlan*",
        "wlan-events*",
        "wlan_events*",
        "wlan-autoconfig*",
        "wlan_autoconfig*",
        "networkprofile*",
        "network-profile*",
        "network_profile*",
        "wifi-history*",
        "wifi_history*",
    ],
    "setupapi_logs": [
        "setupapi*",
        "Setupapi*",
        "setupapi.dev*",
        "setupapi.log*",
    ],
    "application_logs": [
        "application-logs*",
        "application_logs*",
        "app-logs*",
        "app_logs*",
    ],
    "registry_sam": [
        "registry-sam*",
        "registry_sam*",
        "reg-report-sam*",
        "reg_report_sam*",
        "sam-registry*",
    ],
    "registry_ntuser": [
        "registry-ntuser*",
        "registry_ntuser*",
        "reg-report-ntuser*",
        "reg_report_ntuser*",
        "ntuser-registry*",
    ],
    "recent_items": [
        "recent-items*",
        "recent_items*",
        "recent-docs*",
        "recent_docs*",
        "recentdocs*",
    ],
    "browser_history": [
        "browser-history*",
        "browser_history*",
        "browsing-history*",
        "web-history*",
    ],
    "powershell_history": [
        "powershell-history*",
        "powershell_history*",
        "consolehost_history*",
        "PSReadLine*",
    ],
    "cmd_history": [
        "cmd-history*",
        "cmd_history*",
        "command-history*",
        "command_history*",
    ],
    "bash_history": [
        "bash-history*",
        "bash_history*",
        ".bash_history*",
        "wsl-bash*",
    ],
    "prefetch": [
        "prefetch*",
        "pf-*",
    ],
    "amcache": [
        "amcache*",
        "reg-report-amcache*",
        "reg_report_amcache*",
    ],
    "shimcache": [
        "shimcache*",
        "appcompat*",
        "shim-cache*",
        "shim_cache*",
    ],
    "srum": [
        "srum*",
        "srudb*",
    ],
    "process_execution": [
        "process-execution*",
        "process_execution*",
        "process-history*",
        "process_history*",
    ],
    "file_listing": [
        "file-listing*",
        "file_listing*",
        "file-list*",
        "file_list*",
        "directory-listing*",
        "directory_listing*",
        "dir-listing*",
    ],
    "windows_timeline": [
        "ActivitiesCache*",
        "activitiescache*",
        "activities-cache*",
        "activities_cache*",
        "windows-timeline*",
        "windows_timeline*",
        "timeline*",
    ],
    "recycle_bin": [
        "recycle-bin*",
        "recycle_bin*",
        "$Recycle*",
        "$recycle*",
        "recycler*",
        "deleted-files*",
        "deleted_files*",
        "回收站*",
    ],
    "lnk_files": [
        "lnk-files*",
        "lnk_files*",
        "shortcuts*",
        "*.lnk",
        "recent-lnk*",
        "recent_lnk*",
        "快捷方式*",
    ],
    "jump_lists": [
        "jump-list*",
        "jump_list*",
        "jumplist*",
        "automatic-destinations*",
        "automatic_destinations*",
        "AutomaticDestinations*",
        "custom-destinations*",
        "custom_destinations*",
        "CustomDestinations*",
        "*.automaticDestinations-ms",
        "*.customDestinations-ms",
    ],
    "sticky_notes": [
        "sticky-notes*",
        "sticky_notes*",
        "stickynotes*",
        "plum.sqlite*",
    ],
    "user_docs": [
        "user-docs*",
        "user_docs*",
        "documents*",
        "desktop-files*",
    ],
    "hash_inventory": [
        "hash-inventory*",
        "hash_inventory*",
        "file-hashes*",
        "file_hashes*",
        "md5-list*",
        "md5_list*",
        "hash-list*",
        "hash_list*",
    ],
    "audio_files": [
        "audio-files*",
        "audio_files*",
        "audio-export*",
        "audio_export*",
        "recordings*",
    ],
    "audio_transcript": [
        "audio-transcript*",
        "audio_transcript*",
        "transcript*",
        "speech-to-text*",
    ],
    "target_file_export": [
        "target-file*",
        "target_file*",
        "extracted-file*",
        "extracted_file*",
        "file-export*",
        "file_export*",
    ],
    "scheduled_tasks": [
        "scheduled-tasks*",
        "scheduled_tasks*",
        "task-scheduler*",
        "task_scheduler*",
        "schtasks*",
    ],
    "event_logs_defender": [
        "event-logs-defender*",
        "event_logs_defender*",
        "defender-events*",
        "defender_events*",
        "windows-defender*",
        "windows_defender*",
        "Operational-Defender*",
    ],
    "event_logs_printservice": [
        "event-logs-print*",
        "event_logs_print*",
        "print-events*",
        "print_events*",
        "printservice*",
        "print-service*",
        "print_service*",
    ],
    "usn_journal": [
        "usn-journal*",
        "usn_journal*",
        "$usnjrnl*",
        "usnjrnl*",
        "change-journal*",
        "change_journal*",
    ],
    "mft_export": [
        "mft-export*",
        "mft_export*",
        "$mft*",
        "mft-records*",
        "mft_records*",
        "mft-analysis*",
        "mft_analysis*",
    ],
    "sqlite_wal": [
        "sqlite-wal*",
        "sqlite_wal*",
        "wal-files*",
        "wal_files*",
        "*-wal",
        "*.db-wal",
    ],
    "etw_traces": [
        "etw-traces*",
        "etw_traces*",
        "etl-files*",
        "etl_files*",
        "*.etl",
        "event-tracing*",
        "event_tracing*",
    ],
    "disk_partition_info": [
        "disk-partition*",
        "disk_partition*",
        "partition-info*",
        "partition_info*",
        "partition-table*",
        "partition_table*",
        "disk-info*",
        "disk_info*",
        "disk-geometry*",
        "disk_geometry*",
    ],
    "volume_info": [
        "volume-info*",
        "volume_info*",
        "filesystem-info*",
        "filesystem_info*",
        "fs-info*",
        "fs_info*",
        "volume-properties*",
        "volume_properties*",
    ],
    "evidence_metadata": [
        "evidence-metadata*",
        "evidence_metadata*",
        "evidence-source*",
        "evidence_source*",
        "image-info*",
        "image_info*",
        "case-evidence*",
        "case_evidence*",
        "acquisition-info*",
        "acquisition_info*",
    ],
}
TABLE_SUFFIXES = {".json", ".jsonl", ".csv", ".tsv", ".txt", ".html", ".htm", ".db"}


class _SimpleTableHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_row = False
        self.in_cell = False
        self.current_cell: list[str] = []
        self.current_row: list[str] = []
        self.rows: list[list[str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "tr":
            self.in_row = True
            self.current_row = []
        elif tag in {"td", "th"} and self.in_row:
            self.in_cell = True
            self.current_cell = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"td", "th"} and self.in_cell:
            self.in_cell = False
            self.current_row.append("".join(self.current_cell).strip())
        elif tag == "tr" and self.in_row:
            self.in_row = False
            if any(cell for cell in self.current_row):
                self.rows.append(self.current_row)

    def handle_data(self, data: str) -> None:
        if self.in_cell:
            self.current_cell.append(data)


def sanitize_filename(name: str) -> str:
    cleaned = INVALID_FILENAME_CHARS_RE.sub("_", name.strip())
    return cleaned or "default"


def read_text_auto(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16", "utf-16le", "gb18030", "cp936", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def parse_msglog(text: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    def flush() -> None:
        nonlocal current
        if current is not None:
            current["message"] = current["message"].strip()
            entries.append(current)
            current = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        match = TIMESTAMP_RE.match(line)
        if match:
            flush()
            timestamp = datetime.strptime(
                f"{match.group('date')} {match.group('time')}", "%Y/%m/%d %H:%M:%S"
            )
            current = {
                "timestamp": timestamp.isoformat(),
                "message": match.group("msg"),
            }
            continue
        if line.startswith("X-Ways Forensics "):
            flush()
            entries.append({"timestamp": None, "message": line})
            continue
        if current is None:
            if line:
                entries.append({"timestamp": None, "message": line})
            continue
        current["message"] = f"{current['message']}\n{line}".strip("\n")
    flush()
    return entries


def filter_messages(
    entries: list[dict[str, Any]],
    *,
    contains: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    filtered = entries
    if contains:
        needle = contains.lower()
        filtered = [
            entry for entry in filtered if needle in entry.get("message", "").lower()
        ]
    if limit > 0:
        filtered = filtered[-limit:]
    return filtered


def extract_snapshot_summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    history: list[dict[str, Any]] = []
    for entry in entries:
        message = entry.get("message", "")
        if "volume snapshot" not in message.lower() and "磁盘快照" not in message:
            continue
        item: dict[str, Any] = {
            "timestamp": entry.get("timestamp"),
            "message": message,
        }
        match = SNAPSHOT_ZH_RE.search(message)
        if match:
            item.update(
                {
                    "total_items": int(match.group("total").replace(",", "")),
                    "previous_items": int(match.group("before").replace(",", "")),
                    "delta_items": int(match.group("delta").replace(",", "")),
                    "duration_minutes_text": match.group("duration"),
                }
            )
        history.append(item)
    return {
        "history": history,
        "latest": history[-1] if history else None,
        "count": len(history),
    }


def extract_search_messages(
    entries: list[dict[str, Any]], search_term: str | None = None
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    needle = search_term.lower() if search_term else None
    for entry in entries:
        message = entry.get("message", "")
        if not SEARCH_HINT_RE.search(message):
            continue
        if needle and needle not in message.lower():
            continue
        results.append(
            {
                "timestamp": entry.get("timestamp"),
                "message": message,
            }
        )
    return results


def extract_encrypted_messages(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for entry in entries:
        message = entry.get("message", "")
        if ENCRYPTED_HINT_RE.search(message):
            results.append(
                {
                    "timestamp": entry.get("timestamp"),
                    "message": message,
                    "reason": "message-log",
                }
            )
    return results


def inventory_files(path: Path, limit: int = 200) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for child in sorted(path.rglob("*")):
        if not child.is_file():
            continue
        stat = child.stat()
        records.append(
            {
                "path": str(child),
                "relative_path": str(child.relative_to(path)),
                "size": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }
        )
        if len(records) >= limit:
            break
    return records


def load_export_records(
    export_dir: Path, kind: str, limit: int = 500
) -> tuple[list[dict[str, Any]], list[str]]:
    if not export_dir.exists():
        return [], []

    files: list[Path] = []
    for pattern in EXPORT_PATTERNS.get(kind, []):
        files.extend(
            sorted(
                [
                    path
                    for path in export_dir.glob(pattern)
                    if path.is_file() and path.suffix.lower() in TABLE_SUFFIXES
                ]
            )
        )
    unique_files = list(dict.fromkeys(files))

    records: list[dict[str, Any]] = []
    for path in unique_files:
        if path.suffix.lower() == ".db" and kind == "windows_timeline":
            records.extend(parse_activities_cache_db(path, limit=max(limit - len(records), 0)))
        else:
            records.extend(_load_table(path, limit=max(limit - len(records), 0)))
        if len(records) >= limit:
            break
    return records[:limit], [str(path) for path in unique_files]


def list_export_files(export_dir: Path, kind: str) -> list[str]:
    if not export_dir.exists():
        return []
    files: list[Path] = []
    for pattern in EXPORT_PATTERNS.get(kind, []):
        files.extend(
            sorted(
                [
                    path
                    for path in export_dir.glob(pattern)
                    if path.is_file() and path.suffix.lower() in TABLE_SUFFIXES
                ]
            )
        )
    return [str(path) for path in dict.fromkeys(files)]


def load_table_file(path: Path, limit: int = 5000) -> list[dict[str, Any]]:
    return _load_table(path, limit=limit)


def _load_table(path: Path, limit: int = 500) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        payload = json.loads(read_text_auto(path))
        if isinstance(payload, list):
            return [_coerce_record(item, path) for item in payload[:limit]]
        return [_coerce_record(payload, path)]
    if suffix == ".jsonl":
        results: list[dict[str, Any]] = []
        for line in read_text_auto(path).splitlines():
            line = line.strip()
            if not line:
                continue
            results.append(_coerce_record(json.loads(line), path))
            if len(results) >= limit:
                break
        return results
    if suffix in {".csv", ".tsv"}:
        delimiter = "\t" if suffix == ".tsv" else ","
        for enc in ("utf-8-sig", "utf-16", "gb18030", "cp1252"):
            try:
                with path.open("r", encoding=enc, newline="") as handle:
                    reader = csv.DictReader(handle, delimiter=delimiter)
                    return [
                        {**row, "_source_file": str(path)}
                        for _, row in zip(range(limit), reader)
                    ]
            except (UnicodeDecodeError, UnicodeError):
                continue
        return []
    if suffix in {".html", ".htm"}:
        parser = _SimpleTableHTMLParser()
        parser.feed(read_text_auto(path))
        if not parser.rows:
            return []
        header = parser.rows[0]
        results = []
        for row in parser.rows[1: limit + 1]:
            padded = row + [""] * max(len(header) - len(row), 0)
            results.append(
                {
                    **dict(zip(header, padded)),
                    "_source_file": str(path),
                }
            )
        return results
    if suffix == ".txt":
        results = []
        for line in read_text_auto(path).splitlines():
            line = line.strip()
            if not line:
                continue
            results.append({"line": line, "_source_file": str(path)})
            if len(results) >= limit:
                break
        return results
    return []


def _coerce_record(item: Any, path: Path) -> dict[str, Any]:
    if isinstance(item, dict):
        record = dict(item)
        if record.get("_source_file"):
            record.setdefault("_canonical_file", str(path))
            return record
        record["_source_file"] = str(path)
        return record
    return {"value": item, "_source_file": str(path)}


def extract_names_from_file(names_file: Path, limit: int = 4000) -> list[str]:
    try:
        text = names_file.read_bytes().decode("utf-16le", errors="ignore")
    except OSError:
        return []
    names: list[str] = []
    seen: set[str] = set()
    for token in text.split("\x00"):
        candidate = token.strip()
        if not _looks_like_name(candidate):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        names.append(candidate)
        if len(names) >= limit:
            break
    return names


def _looks_like_name(value: str) -> bool:
    if len(value) < 2 or len(value) > 260:
        return False
    if not LIKELY_NAME_RE.search(value):
        return False
    if value.count(":") > 1:
        return False
    printable = sum(1 for ch in value if ch.isprintable())
    if printable / len(value) < 0.8:
        return False
    return True


def build_encrypted_candidates(
    names: list[str], *, source_file: str, limit: int = 200
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in names:
        lowered = name.lower()
        reason: str | None = None
        suffix = Path(lowered).suffix
        if suffix in ENCRYPTED_EXTENSIONS:
            reason = f"extension:{suffix}"
        elif any(keyword in lowered for keyword in ENCRYPTED_KEYWORDS):
            reason = "keyword-match"
        if not reason or lowered in seen:
            continue
        seen.add(lowered)
        results.append(
            {
                "name": name,
                "reason": reason,
                "source": "names-heuristic",
                "_source_file": source_file,
            }
        )
        if len(results) >= limit:
            break
    return results
