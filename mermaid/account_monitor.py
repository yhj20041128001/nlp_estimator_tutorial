#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MySQL / TiDB 数据库账号安全监控脚本

监控功能：
  F1 - 新账号创建告警（轮询 mysql.user 对比）
  F2 - 高危账号登录告警（dba_root / root 出现在 PROCESSLIST）
  F3 - 休眠账号激活告警（账号距上次活跃超过阈值后再次出现）
  F4 - 账号权限变更告警（mysql.user 权限字段发生变化）

配置文件：.account_monitor.yml（与脚本同目录）
状态文件：account_monitor_state.json（与脚本同目录，自动生成）
Python 版本：3.6+
"""

import hashlib
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import mysql.connector
import requests
import yaml

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / ".account_monitor.yml"

# mysql.user 中需要监控的权限字段（MySQL 5.7+ / TiDB 兼容）
PRIV_COLUMNS = [
    "Select_priv", "Insert_priv", "Update_priv", "Delete_priv",
    "Create_priv", "Drop_priv", "Grant_priv", "References_priv",
    "Index_priv", "Alter_priv", "Show_db_priv", "Super_priv",
    "Create_tmp_table_priv", "Lock_tables_priv", "Execute_priv",
    "Repl_slave_priv", "Repl_client_priv", "Create_view_priv",
    "Show_view_priv", "Create_routine_priv", "Alter_routine_priv",
    "Create_user_priv", "Event_priv", "Trigger_priv",
    "Create_tablespace_priv",
]


# ===========================================================================
# T1 — 配置层 + 日志初始化
# ===========================================================================

def load_config():
    """加载 YAML 配置文件，文件不存在时退出。"""
    if not CONFIG_FILE.exists():
        sys.exit(f"[ERROR] 配置文件不存在: {CONFIG_FILE}\n"
                 f"请参考 .account_monitor.yml.example 创建配置文件。")
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def setup_logging(log_file: str) -> logging.Logger:
    """初始化日志，同时输出到文件和控制台。"""
    logger = logging.getLogger("account_monitor")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    log_path = str(BASE_DIR / log_file)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    return logger


def get_proxies(config: dict):
    """根据配置返回代理 dict，未启用则返回 None。"""
    proxy_cfg = config.get("proxy", {})
    if not proxy_cfg.get("enabled", False):
        return None
    return {
        "http": proxy_cfg.get("http", ""),
        "https": proxy_cfg.get("https", ""),
    }


# ===========================================================================
# T2 — 状态层（StateStore，JSON 持久化）
# ===========================================================================

class StateStore:
    """
    将运行状态（账号快照、最近活跃时间）持久化到中央存储库。
      - user_snapshot: {node_key: {user@host: priv_hash}}
      - last_active:   {node_key: {user: iso_timestamp}}
    """

    def __init__(self, config: dict):
        self._config = config
        self._data: dict = self._load()

    def _get_conn(self):
        return get_storage_connection(self._config)

    def _state_table(self) -> str:
        return self._config.get("storage_db", {}).get("state_table", "account_monitor_state")

    def _load(self) -> dict:
        data = {}
        conn = None
        try:
            conn = self._get_conn()
            if conn is None:
                return data
            table = self._state_table()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT node_key, state_type, user_key, state_value FROM `%s`" % table
            )
            for row in cursor.fetchall():
                (data.setdefault(row["node_key"], {})
                     .setdefault(row["state_type"], {})[row["user_key"]]) = row["state_value"]
            cursor.close()
        except Exception as e:
            logging.getLogger("account_monitor").warning("状态从数据库加载失败，重新初始化: %s", e)
        finally:
            if conn and conn.is_connected():
                conn.close()
        return data

    def save(self):
        """将内存状态同步到数据库（先删后插，保证已删除的账号不残留）。"""
        conn = None
        try:
            conn = self._get_conn()
            if conn is None:
                return
            table = self._state_table()
            cursor = conn.cursor()
            for nk, types in self._data.items():
                for st, users in types.items():
                    cursor.execute(
                        "DELETE FROM `%s` WHERE node_key=%%s AND state_type=%%s" % table,
                        (nk, st),
                    )
                    for uk, sv in users.items():
                        cursor.execute(
                            "INSERT INTO `%s` (node_key, state_type, user_key, state_value) "
                            "VALUES (%%s,%%s,%%s,%%s)" % table,
                            (nk, st, uk, sv),
                        )
            conn.commit()
            cursor.close()
        except Exception as e:
            logging.getLogger("account_monitor").error("状态写入数据库失败: %s", e)
        finally:
            if conn and conn.is_connected():
                conn.close()

    # --- user_snapshot ---

    def get_user_snapshot(self, node_key: str) -> dict:
        return self._data.get(node_key, {}).get("user_snapshot", {})

    def set_user_snapshot(self, node_key: str, snapshot: dict):
        self._data.setdefault(node_key, {})["user_snapshot"] = snapshot

    # --- last_active ---

    def get_last_active(self, node_key: str) -> dict:
        return self._data.get(node_key, {}).get("last_active", {})

    def set_last_active(self, node_key: str, user_key: str, ts: datetime):
        self._data.setdefault(node_key, {}).setdefault("last_active", {})
        self._data[node_key]["last_active"][user_key] = ts.isoformat()


# ===========================================================================
# T3 — 数据库查询层
# ===========================================================================

def get_connection(db_info: dict):
    """创建 mysql.connector 连接，超时 5 秒。"""
    return mysql.connector.connect(
        host=db_info["host"],
        port=db_info["port"],
        user=db_info["username"],
        password=db_info["password"],
        database="mysql",
        connection_timeout=5,
    )


def fetch_users(conn) -> list:
    """
    查询 mysql.user，返回包含 User / Host / 所有 *_priv 字段的字典列表。
    TiDB 兼容（部分字段固定为 N，不影响对比逻辑）。
    """
    cols = ", ".join(PRIV_COLUMNS)
    sql = f"SELECT User, Host, {cols} FROM mysql.user"
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(sql)
        return cursor.fetchall()
    finally:
        cursor.close()


def fetch_processlist(conn) -> list:
    """
    查询 information_schema.PROCESSLIST，过滤 Sleep 连接。
    返回 ID / USER / HOST / DB / TIME / COMMAND 字典列表。
    """
    sql = """
        SELECT ID, USER, HOST, DB, TIME, COMMAND
        FROM information_schema.PROCESSLIST
        WHERE COMMAND != 'Sleep'
    """
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(sql)
        return cursor.fetchall()
    finally:
        cursor.close()


def make_user_key(user: str, host: str) -> str:
    """返回 'user@host' 格式的账号唯一标识。"""
    return f"{user}@{host}"


def make_priv_hash(row: dict) -> str:
    """对行中所有 *_priv 字段的值拼接后做 SHA256，用于权限对比。"""
    values = "".join(str(row.get(col, "N")) for col in PRIV_COLUMNS)
    return hashlib.sha256(values.encode()).hexdigest()


def extract_client_ip(host_field: str) -> str:
    """从 PROCESSLIST.HOST 字段（格式为 ip:port）中提取 IP 部分。"""
    return host_field.split(":")[0] if host_field else "unknown"


def parse_isoformat(s):
    """解析 ISO 格式时间字符串，兼容 Python 3.6（不支持 datetime.fromisoformat）。"""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError("无法解析时间格式: %s" % s)


# ===========================================================================
# T4 — 检测层：F1 新账号 + F4 权限变更
# ===========================================================================

def _build_snapshot(rows: list) -> tuple:
    """
    根据 fetch_users 返回的行构建：
      - snapshot: {user@host: priv_hash}
      - rows_map:  {user@host: row_dict}
    """
    snapshot = {}
    rows_map = {}
    for r in rows:
        key = make_user_key(r["User"], r["Host"])
        snapshot[key] = make_priv_hash(r)
        rows_map[key] = r
    return snapshot, rows_map


def check_new_accounts(current_snapshot: dict, known_snapshot: dict, logger, node_key: str) -> list:
    """
    F1：检测新建账号。
    首轮（known_snapshot 为空）不告警，仅由调用方初始化快照。
    后续发现新用户行则返回告警列表。
    """
    alerts = []
    if known_snapshot:
        new_users = set(current_snapshot) - set(known_snapshot)
        for user_key in sorted(new_users):
            user, host = user_key.split("@", 1)
            logger.warning("[F1] 新账号: %s (node=%s)", user_key, node_key)
            alerts.append({"user": user, "host": host})
    return alerts


def check_priv_changes(current_snapshot: dict, rows_map: dict, known_snapshot: dict, logger, node_key: str) -> list:
    """
    F4：检测权限变更。
    对比当前与已知快照中已存在账号的权限哈希。
    首轮（known_snapshot 为空）不告警。
    """
    alerts = []
    if known_snapshot:
        for user_key in set(current_snapshot) & set(known_snapshot):
            if current_snapshot[user_key] != known_snapshot[user_key]:
                user, host = user_key.split("@", 1)
                row = rows_map[user_key]
                new_privs = {col: row[col] for col in PRIV_COLUMNS if col in row}
                logger.warning("[F4] 权限变更: %s (node=%s)", user_key, node_key)
                alerts.append({"user": user, "host": host, "new_privs": new_privs})
    return alerts


# ===========================================================================
# T5 — 检测层：F2 高危账号登录 + F3 休眠账号激活
# ===========================================================================

def check_high_risk_logins(conn, config: dict, logger) -> list:
    """
    F2：检测高危账号（dba_root / root 等）出现在 PROCESSLIST。
    无状态，每轮均检测并返回。
    """
    high_risk = set(config.get("monitor", {}).get("high_risk_users", []))
    if not high_risk:
        return []

    processes = fetch_processlist(conn)
    alerts = []
    for row in processes:
        if row["USER"] in high_risk:
            logger.warning("[F2] 高危账号登录: user=%s host=%s", row["USER"], row["HOST"])
            alerts.append({
                "user": row["USER"],
                "client_host": extract_client_ip(row["HOST"] or ""),
                "db": row["DB"] or "N/A",
            })
    return alerts


def check_dormant_logins(conn, node_key: str, state: StateStore, config: dict, logger) -> list:
    """
    F3：检测休眠账号激活。
    若账号距上次活跃时间超过任一阈值，触发告警。
    首次出现在 PROCESSLIST 的账号记录时间，不告警。
    告警后更新 last_seen，防止同一连接持续重复告警。
    """
    thresholds_days = config.get("monitor", {}).get("dormant_thresholds_days", [1, 7, 30])
    min_threshold_seconds = min(thresholds_days) * 86400

    processes = fetch_processlist(conn)
    last_active = state.get_last_active(node_key)
    now = datetime.now()
    alerts = []
    alerted_users = set()

    for row in processes:
        user = row["USER"]
        client_host = extract_client_ip(row["HOST"] or "")
        # 用 user 作为 key（同一账号不同来源IP合并判断）
        user_key = user

        if user_key in alerted_users:
            continue

        last_seen_str = last_active.get(user_key)

        if last_seen_str is None:
            # 首次出现，记录时间，不告警
            state.set_last_active(node_key, user_key, now)
            continue

        last_seen = parse_isoformat(last_seen_str)
        delta = now - last_seen
        delta_seconds = delta.total_seconds()

        if delta_seconds >= min_threshold_seconds:
            delta_days = delta.days
            logger.warning(
                "[F3] 休眠账号激活: user=%s 距上次活跃 %d 天 (node=%s)",
                user, delta_days, node_key,
            )
            alerts.append({
                "user": user,
                "client_host": client_host,
                "last_seen": last_seen_str,
                "delta_days": delta_days,
            })
            alerted_users.add(user_key)

        # 每次出现都更新 last_seen（无论是否告警）
        state.set_last_active(node_key, user_key, now)

    return alerts


# ===========================================================================
# T6 — 推送层（Telegram）
# ===========================================================================

_ALERT_ICONS = {
    "new_account":    "👤",
    "high_risk_login": "🚨",
    "dormant_login":  "😴",
    "priv_change":    "🔑",
    "error":          "❌",
}

_ALERT_TITLES = {
    "new_account":    "新账号创建告警",
    "high_risk_login": "高危账号登录告警",
    "dormant_login":  "休眠账号激活告警",
    "priv_change":    "账号权限变更告警",
    "error":          "监控异常告警",
}


def _format_message(db_info: dict, alert_type: str, fields: dict) -> str:
    """根据告警类型格式化 Telegram 消息文本。"""
    icon = _ALERT_ICONS.get(alert_type, "⚠️")
    title = _ALERT_TITLES.get(alert_type, "告警")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header = (
        f"【{title}】{icon}\n"
        f"项目名称: {db_info.get('note', '')}\n"
        f"部门: {db_info.get('tenant', '')}\n"
        f"项目: {db_info.get('dbProject', '')}\n"
        f"主机名: {db_info.get('hostname', '')}\n"
        f"主机IP: {db_info.get('host', '')}\n"
        f"数据库类型: {db_info.get('dbType', 'mysql').upper()}\n"
    )

    if alert_type == "new_account":
        body = (
            f"新账号: {fields.get('user')}@{fields.get('host')}\n"
            f"发现时间: {now_str}\n"
        )
    elif alert_type == "high_risk_login":
        body = (
            f"高危账号: {fields.get('user')}\n"
            f"来源IP: {fields.get('client_host')}\n"
            f"所属库: {fields.get('db')}\n"
            f"登录时间: {now_str}\n"
        )
    elif alert_type == "dormant_login":
        body = (
            f"账号: {fields.get('user')}\n"
            f"来源IP: {fields.get('client_host')}\n"
            f"上次活跃: {fields.get('last_seen')}\n"
            f"休眠时长: {fields.get('delta_days')} 天\n"
            f"发现时间: {now_str}\n"
        )
    elif alert_type == "priv_change":
        privs = fields.get("new_privs", {})
        granted = [k for k, v in privs.items() if v == "Y"]
        body = (
            f"账号: {fields.get('user')}@{fields.get('host')}\n"
            f"当前授权: {', '.join(granted) if granted else '(无)'}\n"
            f"变更时间: {now_str}\n"
        )
    else:  # error
        body = f"错误信息: {fields.get('error_msg', '')}\n"

    return header + body


def push_alert(config: dict, db_info: dict, alert_type: str, fields: dict, logger):
    """发送 Telegram 告警，失败只记日志，不抛异常。"""
    tg_cfg = config.get("telegram", {})
    if not tg_cfg.get("enabled", False):
        return

    token = tg_cfg["token"]
    chat_id = tg_cfg["chat_id"]
    push_url = f"https://api.telegram.org/bot{token}/sendMessage"
    proxies = get_proxies(config)
    text = _format_message(db_info, alert_type, fields)

    payload = json.dumps({"chat_id": chat_id, "text": text})
    headers = {
        "content-type": "application/json; charset=UTF-8",
        "Accept": "application/json",
    }

    try:
        resp = requests.post(
            url=push_url, headers=headers, data=payload,
            proxies=proxies, verify=False, timeout=10,
        )
        if resp.status_code == 200:
            logger.info("Telegram 告警发送成功 [%s] chat_id=%s", alert_type, chat_id)
        else:
            logger.error(
                "Telegram 告警发送失败 [%s] status=%s body=%s",
                alert_type, resp.status_code, resp.text,
            )
    except Exception as e:
        logger.error("Telegram 告警发送异常 [%s]: %s", alert_type, e)


# ===========================================================================
# T6b — 存储层（告警事件写入 MySQL）
# ===========================================================================

_CREATE_STATE_TABLE_SQL_TPL = """
CREATE TABLE IF NOT EXISTS `{table}` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `node_key`    VARCHAR(100) NOT NULL COMMENT '被监控节点 host:port',
  `state_type`  VARCHAR(50)  NOT NULL COMMENT 'user_snapshot / last_active',
  `user_key`    VARCHAR(200) NOT NULL COMMENT 'user@host 或 user',
  `state_value` VARCHAR(500) NOT NULL COMMENT 'priv_hash 或 ISO时间戳',
  `updated_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_state` (`node_key`, `state_type`, `user_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='账号监控运行状态';
"""

_CREATE_TABLE_SQL_TPL = """
CREATE TABLE IF NOT EXISTS `{table}` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `node_key`    VARCHAR(100) NOT NULL COMMENT '被监控节点 host:port',
  `note`        VARCHAR(200) DEFAULT NULL COMMENT '节点备注名',
  `tenant`      VARCHAR(200) DEFAULT NULL COMMENT '部门',
  `db_project`  VARCHAR(200) DEFAULT NULL COMMENT '项目',
  `hostname`    VARCHAR(200) DEFAULT NULL COMMENT '主机名',
  `db_type`     VARCHAR(50)  DEFAULT NULL COMMENT '数据库类型',
  `alert_type`  VARCHAR(50)  NOT NULL     COMMENT 'new_account/high_risk_login/dormant_login/priv_change',
  `alert_user`  VARCHAR(200) DEFAULT NULL COMMENT '相关账号',
  `alert_host`  VARCHAR(200) DEFAULT NULL COMMENT '账号Host或来源IP',
  `detail`      TEXT         DEFAULT NULL COMMENT '告警详情JSON',
  `created_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='数据库账号监控告警事件';
"""


def get_storage_connection(config):
    """创建存储数据库连接，storage_db 未启用则返回 None。"""
    st_cfg = config.get("storage_db", {})
    if not st_cfg.get("enabled", False):
        return None
    return mysql.connector.connect(
        host=st_cfg["host"],
        port=st_cfg["port"],
        user=st_cfg["username"],
        password=st_cfg["password"],
        database=st_cfg["database"],
        connection_timeout=5,
    )


def init_storage_table(config, logger):
    """启动时自动创建告警事件表和状态表（若不存在）。"""
    st_cfg = config.get("storage_db", {})
    if not st_cfg.get("enabled", False):
        return
    events_table = st_cfg.get("table", "account_monitor_events")
    state_table = st_cfg.get("state_table", "account_monitor_state")
    conn = None
    try:
        conn = get_storage_connection(config)
        cursor = conn.cursor()
        cursor.execute(_CREATE_TABLE_SQL_TPL.format(table=events_table))
        cursor.execute(_CREATE_STATE_TABLE_SQL_TPL.format(table=state_table))
        conn.commit()
        cursor.close()
        logger.info("存储库初始化完成，表: %s.%s, %s.%s",
                    st_cfg["database"], events_table,
                    st_cfg["database"], state_table)
    except Exception as e:
        logger.error("存储库初始化失败: %s", e)
    finally:
        if conn and conn.is_connected():
            conn.close()


def save_alert_event(config, db_info, alert_type, fields, logger):
    """将告警事件写入中央存储数据库，失败只记日志不影响主流程。"""
    st_cfg = config.get("storage_db", {})
    if not st_cfg.get("enabled", False):
        return
    node_key = "%s:%s" % (db_info["host"], db_info["port"])
    alert_user = fields.get("user", "")
    alert_host = fields.get("host") or fields.get("client_host", "")
    detail = json.dumps(fields, ensure_ascii=False, default=str)
    table = st_cfg.get("table", "account_monitor_events")
    sql = (
        "INSERT INTO `%s` "
        "(node_key, note, tenant, db_project, hostname, db_type, "
        " alert_type, alert_user, alert_host, detail) "
        "VALUES (%%s,%%s,%%s,%%s,%%s,%%s,%%s,%%s,%%s,%%s)" % table
    )
    conn = None
    try:
        conn = get_storage_connection(config)
        cursor = conn.cursor()
        cursor.execute(sql, (
            node_key,
            db_info.get("note", ""),
            db_info.get("tenant", ""),
            db_info.get("dbProject", ""),
            db_info.get("hostname", ""),
            db_info.get("dbType", "mysql"),
            alert_type,
            alert_user,
            alert_host,
            detail,
        ))
        conn.commit()
        cursor.close()
    except Exception as e:
        logger.error("告警事件写入存储库失败 [%s]: %s", alert_type, e)
    finally:
        if conn and conn.is_connected():
            conn.close()


# ===========================================================================
# T7 — 主控层
# ===========================================================================

def process_node(config: dict, db_info: dict, state: StateStore, logger):
    """对单个数据库节点执行一轮完整监控。"""
    node_key = f"{db_info['host']}:{db_info['port']}"
    label = f"{db_info.get('note', '')}({node_key})"
    logger.info("轮询节点 [%s] dbType=%s", label, db_info.get("dbType", "mysql"))

    conn = None
    try:
        conn = get_connection(db_info)

        # F1 + F4 共享同一次 fetch_users，读取旧快照后统一更新
        user_rows = fetch_users(conn)
        current_snapshot, rows_map = _build_snapshot(user_rows)
        known_snapshot = state.get_user_snapshot(node_key)

        new_account_alerts = check_new_accounts(current_snapshot, known_snapshot, logger, node_key)
        priv_change_alerts = check_priv_changes(current_snapshot, rows_map, known_snapshot, logger, node_key)

        # 两项检测完成后统一更新快照（保证 F1/F4 都读到同一份旧快照）
        state.set_user_snapshot(node_key, current_snapshot)

        high_risk_alerts = check_high_risk_logins(conn, config, logger)
        dormant_alerts = check_dormant_logins(conn, node_key, state, config, logger)

        # 推送 + 入库 F1 告警
        for fields in new_account_alerts:
            push_alert(config, db_info, "new_account", fields, logger)
            save_alert_event(config, db_info, "new_account", fields, logger)

        # 推送 + 入库 F4 告警
        for fields in priv_change_alerts:
            push_alert(config, db_info, "priv_change", fields, logger)
            save_alert_event(config, db_info, "priv_change", fields, logger)

        # 推送 + 入库 F2 告警
        for fields in high_risk_alerts:
            push_alert(config, db_info, "high_risk_login", fields, logger)
            save_alert_event(config, db_info, "high_risk_login", fields, logger)

        # 推送 + 入库 F3 告警
        for fields in dormant_alerts:
            push_alert(config, db_info, "dormant_login", fields, logger)
            save_alert_event(config, db_info, "dormant_login", fields, logger)

        # 持久化本轮状态变更
        state.save()

        total = len(new_account_alerts) + len(priv_change_alerts) + \
                len(high_risk_alerts) + len(dormant_alerts)
        if total == 0:
            logger.info("[%s] 本轮无告警", label)
        else:
            logger.info("[%s] 本轮发出 %d 条告警", label, total)

    except mysql.connector.Error as e:
        logger.error("[%s] 数据库连接或查询失败: %s", label, e)
        push_alert(config, db_info, "error", {"error_msg": str(e)}, logger)
    except Exception as e:
        logger.error("[%s] 未预期异常: %s", label, e)
    finally:
        if conn and conn.is_connected():
            conn.close()


def main():
    config = load_config()
    monitor_cfg = config.get("monitor", {})

    log_file = monitor_cfg.get("log_file", "account_monitor.log")
    logger = setup_logging(log_file)

    state = StateStore(config)

    poll_interval = monitor_cfg.get("poll_interval", 30)
    databases = config.get("databases", [])
    if not databases:
        sys.exit("[ERROR] 配置文件中没有任何数据库节点")

    logger.info("=== 数据库账号监控启动 ===")
    logger.info("  配置文件: %s", CONFIG_FILE)
    logger.info("  轮询间隔: %ds", poll_interval)
    logger.info("  高危账号: %s", monitor_cfg.get("high_risk_users", []))
    logger.info("  休眠阈值: %s 天", monitor_cfg.get("dormant_thresholds_days", []))
    logger.info("  Telegram: %s", "启用" if config.get("telegram", {}).get("enabled") else "未启用")
    logger.info("  代理:     %s", "启用" if config.get("proxy", {}).get("enabled") else "未启用")
    st_cfg = config.get("storage_db", {})
    if st_cfg.get("enabled"):
        logger.info("  存储库:   启用 -> %s:%s/%s",
                    st_cfg.get("host", ""), st_cfg.get("port", ""), st_cfg.get("database", ""))
    else:
        logger.info("  存储库:   未启用")
    for db in databases:
        logger.info(
            "  [%s] %s:%s  dbType=%s",
            db.get("note", ""), db["host"], db["port"], db.get("dbType", "mysql"),
        )

    # 初始化告警事件存储表（在所有日志输出之后执行）
    init_storage_table(config, logger)

    print("账号安全监控守护进程已启动，按 Ctrl+C 停止。")

    try:
        while True:
            for db in databases:
                process_node(config, db, state, logger)
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        logger.info("=== 监控已停止 ===")
        print("监控已终止。")


if __name__ == "__main__":
    main()
