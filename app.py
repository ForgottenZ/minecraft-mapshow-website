import base64
import json
import random
import smtplib
import sqlite3
import threading
import time
import urllib.request
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"
CONFIG_PATH = BASE_DIR / "config.json"


def load_config():
    default_config = {
        "secret_key": "dev-secret-key",
        "debug": False,
        "mcmap_dir": "mcmap",
        "smtp": {
            "host": "",
            "port": 587,
            "user": "",
            "password": "",
            "from": "",
            "use_tls": True,
            "oauth2": {
                "enabled": False,
                "tenant_id": "",
                "client_id": "",
                "client_secret": "",
                "refresh_token": "",
            },
        },
    }
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(
            json.dumps(default_config, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return default_config
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    merged = {**default_config, **config}
    merged["smtp"] = {**default_config["smtp"], **config.get("smtp", {})}
    merged["smtp"]["oauth2"] = {
        **default_config["smtp"]["oauth2"],
        **merged["smtp"].get("oauth2", {}),
    }
    return merged


CONFIG = load_config()
MCMAP_DIR = Path(CONFIG.get("mcmap_dir", "mcmap"))
if not MCMAP_DIR.is_absolute():
    MCMAP_DIR = BASE_DIR / MCMAP_DIR

app = Flask(__name__)
app.secret_key = CONFIG.get("secret_key", "dev-secret-key")

_maps_cache = []
_maps_lock = threading.Lock()
_last_scan_at = None
_scan_thread_started = False


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login TEXT
            );

            CREATE TABLE IF NOT EXISTS downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                map_name TEXT NOT NULL,
                downloaded_at TEXT NOT NULL,
                threaded_count INTEGER NOT NULL DEFAULT 1,
                threaded_mark INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS download_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                attempted_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                color TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS map_tags (
                map_name TEXT NOT NULL,
                tag_id INTEGER NOT NULL,
                PRIMARY KEY (map_name, tag_id),
                FOREIGN KEY(tag_id) REFERENCES tags(id)
            );

            CREATE TABLE IF NOT EXISTS map_descriptions (
                map_name TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                display_name TEXT,
                version TEXT
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_flags (
                user_id INTEGER NOT NULL,
                tag TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                expires_at TEXT,
                PRIMARY KEY (user_id, tag),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS operation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_user_id INTEGER,
                action TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL,
                ip_address TEXT,
                FOREIGN KEY(actor_user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS rate_limit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                identifier TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(users)")
        }
        if "email" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "email_verified" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
        if "disabled_until" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN disabled_until TEXT")
        download_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(downloads)")
        }
        if "threaded_count" not in download_columns:
            conn.execute("ALTER TABLE downloads ADD COLUMN threaded_count INTEGER NOT NULL DEFAULT 1")
        if "threaded_mark" not in download_columns:
            conn.execute("ALTER TABLE downloads ADD COLUMN threaded_mark INTEGER NOT NULL DEFAULT 0")
        tag_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(tags)")
        }
        if "is_global" not in tag_columns:
            conn.execute("ALTER TABLE tags ADD COLUMN is_global INTEGER NOT NULL DEFAULT 1")
            conn.execute("UPDATE tags SET is_global=1 WHERE is_global IS NULL")
        if "color" not in tag_columns:
            conn.execute("ALTER TABLE tags ADD COLUMN color TEXT")
        map_description_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(map_descriptions)")
        }
        if "display_name" not in map_description_columns:
            conn.execute("ALTER TABLE map_descriptions ADD COLUMN display_name TEXT")
        if "version" not in map_description_columns:
            conn.execute("ALTER TABLE map_descriptions ADD COLUMN version TEXT")
        defaults = {
            "registration_enabled": "1",
            "registration_mode": "none",
            "registration_default_enabled": "1",
            "site_title": "Minecraft 地图展示",
            "site_subtitle": "游客可浏览，登录后下载，管理员可管理标签与用户。",
            "site_icon_path": "",
            "email_domain_policy": "none",
            "email_domain_list": "",
            "register_limit_ip_count": "5",
            "register_limit_ip_window_minutes": "60",
            "register_limit_session_count": "3",
            "register_limit_session_window_minutes": "60",
            "email_code_limit_ip_count": "5",
            "email_code_limit_ip_window_minutes": "10",
            "email_code_limit_session_count": "3",
            "email_code_limit_session_window_minutes": "10",
            "download_limit_count": "5",
            "download_limit_window_seconds": "60",
            "multithread_window_seconds": "10",
            "multithread_threshold": "3",
            "multithread_tag_expire_minutes": "10",
            "multithread_disable_threshold": "3",
            "multithread_disable_minutes": "60",
            "multithread_disable_mode": "temporary",
        }
        for key, value in defaults.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                (key, value),
            )


def get_setting(key, default=None):
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if not row:
        return default
    return row["value"]


def set_setting(key, value):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


def get_session_id():
    session_id = session.get("rate_session_id")
    if not session_id:
        session_id = f"sess-{random.randint(100000, 999999)}-{int(time.time())}"
        session["rate_session_id"] = session_id
    return session_id


def log_action(action, detail=None, actor_user_id=None):
    ip_address = None
    if request:
        ip_address = get_client_ip()
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO operation_logs (actor_user_id, action, detail, created_at, ip_address)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                actor_user_id,
                action,
                detail,
                datetime.utcnow().isoformat(),
                ip_address,
            ),
        )


def get_registration_config():
    enabled = get_setting("registration_enabled", "1") == "1"
    mode = get_setting("registration_mode", "none")
    if mode not in {"none", "email"}:
        mode = "none"
    return enabled, mode


def parse_domain_list(domain_list_value):
    raw_items = domain_list_value.replace("\n", ",").replace(" ", ",").split(",")
    domains = []
    for item in raw_items:
        value = item.strip()
        if not value:
            continue
        if not value.startswith("@"):
            value = f"@{value}"
        if value not in domains:
            domains.append(value)
    return domains


def get_email_domain_policy():
    policy = get_setting("email_domain_policy", "none")
    if policy not in {"none", "whitelist", "blacklist"}:
        policy = "none"
    domain_list_value = get_setting("email_domain_list", "")
    domains = parse_domain_list(domain_list_value)
    return policy, domains


def get_rate_limit_value(key, default):
    try:
        value = int(get_setting(key, str(default)))
    except ValueError:
        value = default
    return max(0, value)


def check_rate_limit(event_type, identifier, window_seconds, max_count):
    if max_count <= 0 or window_seconds <= 0:
        return True
    since_time = datetime.utcnow() - timedelta(seconds=window_seconds)
    with get_db() as conn:
        count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM rate_limit_events
            WHERE event_type = ? AND identifier = ? AND created_at >= ?
            """,
            (event_type, identifier, since_time.isoformat()),
        ).fetchone()["count"]
    return count < max_count


def record_rate_limit_event(event_type, identifier):
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO rate_limit_events (event_type, identifier, created_at)
            VALUES (?, ?, ?)
            """,
            (event_type, identifier, datetime.utcnow().isoformat()),
        )


def cleanup_user_flags(user_id):
    now_iso = datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute(
            "DELETE FROM user_flags WHERE user_id=? AND expires_at IS NOT NULL AND expires_at < ?",
            (user_id, now_iso),
        )


def add_user_flag(user_id, tag, expire_minutes):
    expires_at = None
    if expire_minutes > 0:
        expires_at = (datetime.utcnow() + timedelta(minutes=expire_minutes)).isoformat()
    with get_db() as conn:
        existing = conn.execute(
            "SELECT count FROM user_flags WHERE user_id=? AND tag=?",
            (user_id, tag),
        ).fetchone()
        if existing:
            new_count = existing["count"] + 1
            conn.execute(
                "UPDATE user_flags SET count=?, expires_at=? WHERE user_id=? AND tag=?",
                (new_count, expires_at, user_id, tag),
            )
        else:
            new_count = 1
            conn.execute(
                "INSERT INTO user_flags (user_id, tag, count, expires_at) VALUES (?, ?, ?, ?)",
                (user_id, tag, new_count, expires_at),
            )
    return new_count


def get_user_flags(user_id):
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM user_flags WHERE user_id=? ORDER BY tag",
            (user_id,),
        ).fetchall()


def normalize_user_status(user):
    if not user:
        return user
    disabled_until = user["disabled_until"]
    if disabled_until:
        try:
            disabled_until_dt = datetime.fromisoformat(disabled_until)
        except ValueError:
            disabled_until_dt = None
        if disabled_until_dt and datetime.utcnow() >= disabled_until_dt:
            with get_db() as conn:
                conn.execute("UPDATE users SET enabled=1, disabled_until=NULL WHERE id=?", (user["id"],))
            return {**dict(user), "enabled": 1, "disabled_until": None}
    return user


def record_download_attempt(user_id):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO download_attempts (user_id, attempted_at) VALUES (?, ?)",
            (user_id, datetime.utcnow().isoformat()),
        )


def count_download_attempts(user_id, window_seconds):
    since_time = datetime.utcnow() - timedelta(seconds=window_seconds)
    with get_db() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS count FROM download_attempts WHERE user_id=? AND attempted_at >= ?",
            (user_id, since_time.isoformat()),
        ).fetchone()["count"]


def build_email_from_form(form):
    email = form.get("email", "").strip()
    local_part = form.get("email_local", "").strip()
    domain = form.get("email_domain", "").strip()
    if local_part and domain:
        if not domain.startswith("@"):
            domain = f"@{domain}"
        email = f"{local_part}{domain}"
    return email


def validate_email_domain(email, policy, domains):
    if policy == "none" or not domains:
        return True
    if "@" not in email:
        return False
    domain = "@" + email.split("@", 1)[1]
    if policy == "whitelist":
        return domain in domains
    if policy == "blacklist":
        return domain not in domains
    return True


def get_oauth2_access_token(oauth_config):
    tenant_id = oauth_config.get("tenant_id")
    client_id = oauth_config.get("client_id")
    client_secret = oauth_config.get("client_secret")
    refresh_token = oauth_config.get("refresh_token")
    if not all([tenant_id, client_id, client_secret, refresh_token]):
        raise ValueError("SMTP OAuth2 配置未完成")
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = (
        "client_id=" + client_id
        + "&client_secret=" + client_secret
        + "&refresh_token=" + refresh_token
        + "&grant_type=refresh_token"
        + "&scope=https%3A%2F%2Foutlook.office365.com%2F.default"
    )
    request_data = data.encode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=request_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    access_token = payload.get("access_token")
    if not access_token:
        raise ValueError("OAuth2 access token 获取失败")
    return access_token


def send_email_code(email_address, code):
    smtp_config = CONFIG.get("smtp", {})
    smtp_host = smtp_config.get("host")
    smtp_port = int(smtp_config.get("port", 587))
    smtp_user = smtp_config.get("user")
    smtp_password = smtp_config.get("password")
    smtp_from = smtp_config.get("from") or smtp_user
    use_tls = bool(smtp_config.get("use_tls", True))
    oauth_config = smtp_config.get("oauth2", {}) if isinstance(smtp_config.get("oauth2"), dict) else {}
    use_oauth2 = bool(oauth_config.get("enabled"))
    if not smtp_host or not smtp_from:
        raise ValueError("SMTP 配置未完成")
    if use_oauth2 and not smtp_user:
        raise ValueError("SMTP OAuth2 需要配置发送邮箱账号")
    message = EmailMessage()
    message["Subject"] = "Minecraft 地图站注册验证码"
    message["From"] = smtp_from
    message["To"] = email_address
    message.set_content(f"你的验证码是：{code}，10 分钟内有效。")
    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
        if use_tls:
            server.starttls()
        if use_oauth2:
            access_token = get_oauth2_access_token(oauth_config)
            auth_string = f"user={smtp_user}\x01auth=Bearer {access_token}\x01\x01"
            server.docmd("AUTH", "XOAUTH2 " + base64.b64encode(auth_string.encode("utf-8")).decode("utf-8"))
        elif smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.send_message(message)


def has_admin():
    with get_db() as conn:
        row = conn.execute("SELECT COUNT(*) AS count FROM users WHERE role='admin'").fetchone()
    return row["count"] > 0


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return normalize_user_status(user)


def require_admin(user):
    if not user or user["role"] != "admin" or not user["enabled"]:
        abort(403)


def find_map_zip(map_name: str, map_dir: Path):
    zip_in_root = MCMAP_DIR / f"{map_name}.zip"
    if zip_in_root.exists():
        return zip_in_root
    zip_in_dir = map_dir / f"{map_name}.zip"
    if zip_in_dir.exists():
        return zip_in_dir
    for candidate in map_dir.glob("*.zip"):
        return candidate
    return None


def find_map_url(map_name: str, map_dir: Path):
    for candidate in MCMAP_DIR.glob("*.url"):
        stem = candidate.stem
        if stem == map_name or stem.startswith(map_name):
            return candidate
    for candidate in map_dir.glob("*.url"):
        stem = candidate.stem
        if stem == map_name or stem.startswith(map_name):
            return candidate
    for candidate in map_dir.glob("*.url"):
        return candidate
    return None


def scan_maps():
    maps = []
    if not MCMAP_DIR.exists():
        return maps

    for entry in sorted(MCMAP_DIR.iterdir()):
        if not entry.is_dir():
            continue
        map_name = entry.name
        zip_path = find_map_zip(map_name, entry)
        if not zip_path:
            continue

        url_file = find_map_url(map_name, entry)
        detail_url = None
        if url_file:
            detail_url = extract_url(url_file)
        maps.append(
            {
                "name": map_name,
                "zip_path": zip_path,
                "detail_url": detail_url,
            }
        )
    return maps


def refresh_map_cache():
    global _maps_cache, _last_scan_at
    maps = scan_maps()
    with _maps_lock:
        _maps_cache = maps
        _last_scan_at = datetime.utcnow()


def get_cached_maps():
    with _maps_lock:
        return list(_maps_cache), _last_scan_at


def start_scan_thread():
    global _scan_thread_started
    if _scan_thread_started:
        return

    refresh_map_cache()

    def loop():
        while True:
            refresh_map_cache()
            time.sleep(60)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    _scan_thread_started = True


def list_directory(path: Path):
    entries = []
    if not path.exists():
        return entries
    for entry in sorted(path.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower())):
        info = {
            "name": entry.name,
            "path": str(entry.resolve()),
            "is_dir": entry.is_dir(),
            "size": entry.stat().st_size if entry.is_file() else None,
        }
        entries.append(info)
    return entries


def make_json_safe(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, timedelta):
        return str(value)
    if isinstance(value, dict):
        return {key: make_json_safe(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [make_json_safe(item) for item in value]
    if isinstance(value, sqlite3.Row):
        return {key: make_json_safe(value[key]) for key in value.keys()}
    return value


def filter_maps(map_items, query, field):
    if not query:
        return map_items
    query_lower = query.lower()
    filtered = []
    for item in map_items:
        name = item["name"].lower()
        display_name = (item.get("display_name") or item["name"]).lower()
        tag_names = [tag["name"].lower() for tag in item.get("tags", [])]
        detail_url = (item.get("detail_url") or "").lower()
        description = (item.get("description") or "").lower()
        matches_title = query_lower in name or query_lower in display_name
        matches_tag = any(query_lower in tag for tag in tag_names)
        matches_content = query_lower in detail_url or query_lower in description
        if field == "title" and matches_title:
            filtered.append(item)
        elif field == "tag" and matches_tag:
            filtered.append(item)
        elif field == "content" and matches_content:
            filtered.append(item)
        elif field == "all" and (matches_title or matches_tag or matches_content):
            filtered.append(item)
    return filtered


def extract_url(url_path: Path):
    try:
        content = url_path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return None
    for line in content.splitlines():
        if line.strip().lower().startswith("url="):
            return line.split("=", 1)[1].strip()
    return None


def get_map_tags(map_name):
    with get_db() as conn:
        return conn.execute(
            """
            SELECT tags.*
            FROM tags
            JOIN map_tags ON tags.id = map_tags.tag_id
            WHERE map_tags.map_name = ?
            ORDER BY tags.name
            """,
            (map_name,),
        ).fetchall()


def get_map_metadata(map_name):
    with get_db() as conn:
        row = conn.execute(
            "SELECT description, display_name, version FROM map_descriptions WHERE map_name=?",
            (map_name,),
        ).fetchone()
    if not row:
        return {"description": "", "display_name": "", "version": ""}
    return {
        "description": row["description"],
        "display_name": row["display_name"] or "",
        "version": row["version"] or "",
    }


def get_global_tags():
    with get_db() as conn:
        return conn.execute("SELECT * FROM tags WHERE is_global=1 ORDER BY name").fetchall()


@app.context_processor
def inject_settings():
    registration_enabled, registration_mode = get_registration_config()
    site_title = get_setting("site_title", "Minecraft 地图展示")
    site_subtitle = get_setting("site_subtitle", "游客可浏览，登录后下载，管理员可管理标签与用户。")
    site_icon_path = get_setting("site_icon_path", "").strip()
    return {
        "registration_enabled": registration_enabled,
        "registration_mode": registration_mode,
        "debug_enabled": bool(CONFIG.get("debug", False)),
        "site_title": site_title or "Minecraft 地图展示",
        "site_subtitle": site_subtitle,
        "site_icon_path": site_icon_path,
        "site_icon_is_url": site_icon_path.startswith("http://")
        or site_icon_path.startswith("https://"),
    }


@app.before_request
def ensure_setup():
    init_db()
    start_scan_thread()
    if request.endpoint in {"setup", "static"}:
        return
    if not has_admin() and request.endpoint not in {"setup", "login", "register"}:
        return redirect(url_for("setup"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if has_admin():
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("请填写用户名和密码。")
        else:
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, role, enabled, created_at)
                    VALUES (?, ?, 'admin', 1, ?)
                    """,
                    (username, generate_password_hash(password), datetime.utcnow().isoformat()),
                )
            flash("管理员账户创建成功，请登录。")
            return redirect(url_for("login"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        user = normalize_user_status(user)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("用户名或密码错误。")
        elif not user["enabled"] or (user["email"] and not user["email_verified"]):
            flash("该账号已被禁用或邮箱未验证。")
        else:
            session.clear()
            session["user_id"] = user["id"]
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET last_login=? WHERE id=?",
                    (datetime.utcnow().isoformat(), user["id"]),
                )
            return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    registration_enabled, registration_mode = get_registration_config()
    email_domain_policy, email_domain_options = get_email_domain_policy()
    if not registration_enabled:
        if request.method == "POST":
            flash("管理员已关闭注册。")
        return render_template(
            "register.html",
            registration_enabled=registration_enabled,
            registration_mode=registration_mode,
            email_domain_policy=email_domain_policy,
            email_domain_options=email_domain_options,
        )
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = build_email_from_form(request.form)
        email_local = request.form.get("email_local", "").strip()
        email_domain = request.form.get("email_domain", "").strip()
        if not email_domain and "@" in email:
            email_domain = "@" + email.split("@", 1)[1]
        password = request.form.get("password", "")
        default_enabled = get_setting("registration_default_enabled", "1") == "1"
        email_verified = 1 if registration_mode == "email" or not email else 0
        if registration_mode == "email":
            code = request.form.get("code", "").strip()
            code_info = session.get("email_code")
            code_sent_at = session.get("email_code_sent_at")
            code_email = session.get("email_code_address")
            if not email or not code or not password:
                flash("请填写邮箱、验证码和密码。")
                return render_template(
                    "register.html",
                    registration_enabled=registration_enabled,
                    registration_mode=registration_mode,
                    email_domain_policy=email_domain_policy,
                    email_domain_options=email_domain_options,
                    email=email,
                    email_local=email_local,
                    email_domain=email_domain,
                )
            if not validate_email_domain(email, email_domain_policy, email_domain_options):
                flash("该邮箱后缀不被允许。")
                return render_template(
                    "register.html",
                    registration_enabled=registration_enabled,
                    registration_mode=registration_mode,
                    email_domain_policy=email_domain_policy,
                    email_domain_options=email_domain_options,
                    email=email,
                    email_local=email_local,
                    email_domain=email_domain,
                )
            if not code_info or not code_sent_at or code_email != email:
                flash("请先获取邮箱验证码。")
                return render_template(
                    "register.html",
                    registration_enabled=registration_enabled,
                    registration_mode=registration_mode,
                    email_domain_policy=email_domain_policy,
                    email_domain_options=email_domain_options,
                    email=email,
                    email_local=email_local,
                    email_domain=email_domain,
                )
            if datetime.utcnow() - datetime.fromisoformat(code_sent_at) > timedelta(minutes=10):
                flash("验证码已过期，请重新获取。")
                return render_template(
                    "register.html",
                    registration_enabled=registration_enabled,
                    registration_mode=registration_mode,
                    email_domain_policy=email_domain_policy,
                    email_domain_options=email_domain_options,
                    email=email,
                    email_local=email_local,
                    email_domain=email_domain,
                )
            if code != code_info:
                flash("验证码错误。")
                return render_template(
                    "register.html",
                    registration_enabled=registration_enabled,
                    registration_mode=registration_mode,
                    email_domain_policy=email_domain_policy,
                    email_domain_options=email_domain_options,
                    email=email,
                    email_local=email_local,
                    email_domain=email_domain,
                )
            username = email
        if registration_mode == "none" and (not username or not password):
            flash("请填写用户名和密码。")
        else:
            client_ip = get_client_ip()
            session_id = get_session_id()
            ip_limit = get_rate_limit_value("register_limit_ip_count", 5)
            ip_window = get_rate_limit_value("register_limit_ip_window_minutes", 60) * 60
            session_limit = get_rate_limit_value("register_limit_session_count", 3)
            session_window = get_rate_limit_value("register_limit_session_window_minutes", 60) * 60
            if not check_rate_limit("register_ip", client_ip, ip_window, ip_limit):
                flash("当前 IP 注册次数过多，请稍后再试。")
                return render_template(
                    "register.html",
                    registration_enabled=registration_enabled,
                    registration_mode=registration_mode,
                    email_domain_policy=email_domain_policy,
                    email_domain_options=email_domain_options,
                    email=email,
                    email_local=email_local,
                    email_domain=email_domain,
                )
            if not check_rate_limit("register_session", session_id, session_window, session_limit):
                flash("当前会话注册次数过多，请稍后再试。")
                return render_template(
                    "register.html",
                    registration_enabled=registration_enabled,
                    registration_mode=registration_mode,
                    email_domain_policy=email_domain_policy,
                    email_domain_options=email_domain_options,
                    email=email,
                    email_local=email_local,
                    email_domain=email_domain,
                )
            try:
                with get_db() as conn:
                    conn.execute(
                        """
                        INSERT INTO users (username, password_hash, role, enabled, created_at, email, email_verified)
                        VALUES (?, ?, 'user', ?, ?, ?, ?)
                        """,
                        (
                            username,
                            generate_password_hash(password),
                            1 if default_enabled else 0,
                            datetime.utcnow().isoformat(),
                            email if email else None,
                            email_verified,
                        ),
                    )
                with get_db() as conn:
                    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
                record_rate_limit_event("register_ip", client_ip)
                record_rate_limit_event("register_session", session_id)
                log_action("user_register", f"username={username}", actor_user_id=user["id"] if user else None)
                session.pop("email_code", None)
                session.pop("email_code_sent_at", None)
                session.pop("email_code_address", None)
                if user and user["enabled"] and (not user["email"] or user["email_verified"]):
                    session.clear()
                    session["user_id"] = user["id"]
                    flash("注册成功，已为你自动登录。")
                    return redirect(url_for("index"))
                flash("注册成功，请等待管理员启用或完成邮箱验证后登录。")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("用户名已存在。")
    email_local = ""
    email_domain = ""
    if "@" in request.args.get("email", ""):
        email_local = request.args.get("email", "").split("@", 1)[0]
        email_domain = "@" + request.args.get("email", "").split("@", 1)[1]
    return render_template(
        "register.html",
        registration_enabled=registration_enabled,
        registration_mode=registration_mode,
        email_domain_policy=email_domain_policy,
        email_domain_options=email_domain_options,
        email_local=email_local,
        email_domain=email_domain,
    )


@app.route("/register/send-code", methods=["POST"])
def register_send_code():
    registration_enabled, registration_mode = get_registration_config()
    if not registration_enabled or registration_mode != "email":
        abort(403)
    email_domain_policy, email_domain_options = get_email_domain_policy()
    email = build_email_from_form(request.form)
    if not email:
        flash("请输入邮箱地址。")
        return redirect(url_for("register"))
    if not validate_email_domain(email, email_domain_policy, email_domain_options):
        flash("该邮箱后缀不被允许。")
        return redirect(url_for("register"))
    client_ip = get_client_ip()
    session_id = get_session_id()
    ip_limit = get_rate_limit_value("email_code_limit_ip_count", 5)
    ip_window = get_rate_limit_value("email_code_limit_ip_window_minutes", 10) * 60
    session_limit = get_rate_limit_value("email_code_limit_session_count", 3)
    session_window = get_rate_limit_value("email_code_limit_session_window_minutes", 10) * 60
    if not check_rate_limit("email_code_ip", client_ip, ip_window, ip_limit):
        flash("当前 IP 发送验证码次数过多，请稍后再试。")
        return redirect(url_for("register"))
    if not check_rate_limit("email_code_session", session_id, session_window, session_limit):
        flash("当前会话发送验证码次数过多，请稍后再试。")
        return redirect(url_for("register"))
    code = f"{random.randint(0, 999999):06d}"
    try:
        send_email_code(email, code)
    except Exception as exc:
        flash(f"验证码发送失败：{exc}")
        return redirect(url_for("register"))
    record_rate_limit_event("email_code_ip", client_ip)
    record_rate_limit_event("email_code_session", session_id)
    log_action("send_email_code", f"email={email}")
    session["email_code"] = code
    session["email_code_sent_at"] = datetime.utcnow().isoformat()
    session["email_code_address"] = email
    flash("验证码已发送，请查收邮箱。")
    return redirect(url_for("register"))


@app.route("/")
def index():
    user = get_current_user()
    maps, _ = get_cached_maps()
    map_items = []
    for item in maps:
        tags = get_map_tags(item["name"])
        metadata = get_map_metadata(item["name"])
        map_items.append(
            {
                **item,
                "tags": tags,
                "display_name": metadata["display_name"] or item["name"],
                "version": metadata["version"],
                "description": metadata["description"],
            }
        )
    query = request.args.get("q", "").strip()
    field = request.args.get("field", "all").strip().lower()
    if field not in {"all", "title", "tag", "content"}:
        field = "all"
    per_page = request.args.get("per_page", "10")
    try:
        per_page_value = int(per_page)
    except ValueError:
        per_page_value = 10
    if per_page_value not in {10, 20, 50}:
        per_page_value = 10
    filtered_items = filter_maps(map_items, query, field)
    total_items = len(filtered_items)
    total_pages = max(1, (total_items + per_page_value - 1) // per_page_value)
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page_value
    end = start + per_page_value
    page_items = filtered_items[start:end]
    return render_template(
        "maps.html",
        user=user,
        maps=page_items,
        query=query,
        field=field,
        page=page,
        per_page=per_page_value,
        total_pages=total_pages,
        total_items=total_items,
        pages=list(range(1, total_pages + 1)),
    )


@app.route("/site-icon")
def site_icon():
    icon_path_value = get_setting("site_icon_path", "").strip()
    if not icon_path_value or icon_path_value.startswith("http://") or icon_path_value.startswith("https://"):
        abort(404)
    icon_path = Path(icon_path_value)
    if not icon_path.is_absolute() or not icon_path.is_file():
        abort(404)
    return send_file(icon_path)


@app.route("/maps/<map_name>")
def map_detail(map_name):
    user = get_current_user()
    maps, _ = get_cached_maps()
    maps = {item["name"]: item for item in maps}
    if map_name not in maps:
        abort(404)
    item = maps[map_name]
    tags = get_map_tags(map_name)
    metadata = get_map_metadata(map_name)
    return render_template(
        "map_detail.html",
        user=user,
        map_item=item,
        tags=tags,
        description=metadata["description"],
        display_name=metadata["display_name"] or item["name"],
        version=metadata["version"],
    )


@app.route("/download/<map_name>")
def download(map_name):
    user = get_current_user()
    if not user or not user["enabled"]:
        flash("请先登录后下载。")
        return redirect(url_for("login"))
    maps, _ = get_cached_maps()
    maps = {item["name"]: item for item in maps}
    if map_name not in maps:
        abort(404)
    record_download_attempt(user["id"])
    download_limit_count = get_rate_limit_value("download_limit_count", 5)
    download_limit_window = get_rate_limit_value("download_limit_window_seconds", 60)
    attempt_count = count_download_attempts(user["id"], download_limit_window)
    if download_limit_count and attempt_count > download_limit_count:
        flash("下载过于频繁，请稍后再试。")
        log_action("download_rate_limited", f"user_id={user['id']}")
        return redirect(url_for("index"))
    multithread_window = get_rate_limit_value("multithread_window_seconds", 10)
    multithread_threshold = get_rate_limit_value("multithread_threshold", 3)
    multithread_hits = count_download_attempts(user["id"], multithread_window)
    is_multithread = multithread_threshold > 0 and multithread_hits >= multithread_threshold
    threaded_count_value = 1
    threaded_mark_value = 1 if is_multithread else 0
    if is_multithread:
        expire_minutes = get_rate_limit_value("multithread_tag_expire_minutes", 10)
        flag_count = add_user_flag(user["id"], "多线程", expire_minutes)
        log_action("user_flag_multithread", f"user_id={user['id']},count={flag_count}")
        disable_threshold = get_rate_limit_value("multithread_disable_threshold", 3)
        disable_mode = get_setting("multithread_disable_mode", "temporary")
        disable_minutes = get_rate_limit_value("multithread_disable_minutes", 60)
        if disable_threshold and flag_count >= disable_threshold:
            with get_db() as conn:
                if disable_mode == "permanent":
                    conn.execute("UPDATE users SET enabled=0, disabled_until=NULL WHERE id=?", (user["id"],))
                    log_action("user_disabled_permanent", f"user_id={user['id']}")
                else:
                    disabled_until = (datetime.utcnow() + timedelta(minutes=disable_minutes)).isoformat()
                    conn.execute(
                        "UPDATE users SET enabled=0, disabled_until=? WHERE id=?",
                        (disabled_until, user["id"]),
                    )
                    log_action(
                        "user_disabled_temporary",
                        f"user_id={user['id']},minutes={disable_minutes}",
                    )
            flash("账号因下载过于频繁被禁用。")
            return redirect(url_for("index"))
    zip_path = maps[map_name]["zip_path"]
    with get_db() as conn:
        if is_multithread:
            since_time = datetime.utcnow() - timedelta(seconds=multithread_window)
            recent = conn.execute(
                """
                SELECT id, threaded_count
                FROM downloads
                WHERE user_id=? AND downloaded_at >= ?
                ORDER BY downloaded_at DESC
                LIMIT 1
                """,
                (user["id"], since_time.isoformat()),
            ).fetchone()
            if recent:
                threaded_count_value = recent["threaded_count"] + 1
                conn.execute(
                    """
                    UPDATE downloads
                    SET threaded_count=?, threaded_mark=1, downloaded_at=?
                    WHERE id=?
                    """,
                    (threaded_count_value, datetime.utcnow().isoformat(), recent["id"]),
                )
                keep_id = recent["id"]
            else:
                cursor = conn.execute(
                    """
                    INSERT INTO downloads (user_id, map_name, downloaded_at, threaded_count, threaded_mark)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (user["id"], map_name, datetime.utcnow().isoformat(), threaded_count_value, threaded_mark_value),
                )
                keep_id = cursor.lastrowid
            conn.execute(
                """
                DELETE FROM downloads
                WHERE user_id=? AND downloaded_at >= ? AND id != ?
                """,
                (user["id"], since_time.isoformat(), keep_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO downloads (user_id, map_name, downloaded_at, threaded_count, threaded_mark)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user["id"], map_name, datetime.utcnow().isoformat(), threaded_count_value, threaded_mark_value),
            )
    return send_file(zip_path, as_attachment=True, download_name=zip_path.name)


@app.route("/admin")
def admin_dashboard():
    user = get_current_user()
    require_admin(user)
    with get_db() as conn:
        user_count = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        download_count = conn.execute("SELECT COUNT(*) AS count FROM downloads").fetchone()[
            "count"
        ]
        tag_count = conn.execute("SELECT COUNT(*) AS count FROM tags").fetchone()["count"]
    registration_enabled, registration_mode = get_registration_config()
    registration_default_enabled = get_setting("registration_default_enabled", "1") == "1"
    email_domain_policy = get_setting("email_domain_policy", "none")
    email_domain_list = get_setting("email_domain_list", "")
    register_limit_ip_count = get_setting("register_limit_ip_count", "5")
    register_limit_ip_window_minutes = get_setting("register_limit_ip_window_minutes", "60")
    register_limit_session_count = get_setting("register_limit_session_count", "3")
    register_limit_session_window_minutes = get_setting("register_limit_session_window_minutes", "60")
    email_code_limit_ip_count = get_setting("email_code_limit_ip_count", "5")
    email_code_limit_ip_window_minutes = get_setting("email_code_limit_ip_window_minutes", "10")
    email_code_limit_session_count = get_setting("email_code_limit_session_count", "3")
    email_code_limit_session_window_minutes = get_setting("email_code_limit_session_window_minutes", "10")
    download_limit_count = get_setting("download_limit_count", "5")
    download_limit_window_seconds = get_setting("download_limit_window_seconds", "60")
    multithread_window_seconds = get_setting("multithread_window_seconds", "10")
    multithread_threshold = get_setting("multithread_threshold", "3")
    multithread_tag_expire_minutes = get_setting("multithread_tag_expire_minutes", "10")
    multithread_disable_threshold = get_setting("multithread_disable_threshold", "3")
    multithread_disable_minutes = get_setting("multithread_disable_minutes", "60")
    multithread_disable_mode = get_setting("multithread_disable_mode", "temporary")
    site_title = get_setting("site_title", "Minecraft 地图展示")
    site_subtitle = get_setting("site_subtitle", "游客可浏览，登录后下载，管理员可管理标签与用户。")
    site_icon_path = get_setting("site_icon_path", "")
    _, last_scan_at = get_cached_maps()
    return render_template(
        "admin_dashboard.html",
        user=user,
        user_count=user_count,
        download_count=download_count,
        tag_count=tag_count,
        registration_enabled=registration_enabled,
        registration_mode=registration_mode,
        registration_default_enabled=registration_default_enabled,
        email_domain_policy=email_domain_policy,
        email_domain_list=email_domain_list,
        register_limit_ip_count=register_limit_ip_count,
        register_limit_ip_window_minutes=register_limit_ip_window_minutes,
        register_limit_session_count=register_limit_session_count,
        register_limit_session_window_minutes=register_limit_session_window_minutes,
        email_code_limit_ip_count=email_code_limit_ip_count,
        email_code_limit_ip_window_minutes=email_code_limit_ip_window_minutes,
        email_code_limit_session_count=email_code_limit_session_count,
        email_code_limit_session_window_minutes=email_code_limit_session_window_minutes,
        download_limit_count=download_limit_count,
        download_limit_window_seconds=download_limit_window_seconds,
        multithread_window_seconds=multithread_window_seconds,
        multithread_threshold=multithread_threshold,
        multithread_tag_expire_minutes=multithread_tag_expire_minutes,
        multithread_disable_threshold=multithread_disable_threshold,
        multithread_disable_minutes=multithread_disable_minutes,
        multithread_disable_mode=multithread_disable_mode,
        last_scan_at=last_scan_at,
        site_title=site_title,
        site_subtitle=site_subtitle,
        site_icon_path=site_icon_path,
    )


@app.route("/admin/settings", methods=["POST"])
def admin_settings():
    user = get_current_user()
    require_admin(user)
    registration_enabled = "1" if request.form.get("registration_enabled") == "on" else "0"
    registration_mode = request.form.get("registration_mode", "none")
    registration_default_enabled = "1" if request.form.get("registration_default_enabled") == "on" else "0"
    email_domain_policy = request.form.get("email_domain_policy", "none")
    email_domain_list = request.form.get("email_domain_list", "").strip()
    if registration_mode not in {"none", "email"}:
        registration_mode = "none"
    if email_domain_policy not in {"none", "whitelist", "blacklist"}:
        email_domain_policy = "none"
    set_setting("registration_enabled", registration_enabled)
    set_setting("registration_mode", registration_mode)
    set_setting("registration_default_enabled", registration_default_enabled)
    set_setting("email_domain_policy", email_domain_policy)
    set_setting("email_domain_list", email_domain_list)
    set_setting("register_limit_ip_count", request.form.get("register_limit_ip_count", "5"))
    set_setting("register_limit_ip_window_minutes", request.form.get("register_limit_ip_window_minutes", "60"))
    set_setting("register_limit_session_count", request.form.get("register_limit_session_count", "3"))
    set_setting("register_limit_session_window_minutes", request.form.get("register_limit_session_window_minutes", "60"))
    set_setting("email_code_limit_ip_count", request.form.get("email_code_limit_ip_count", "5"))
    set_setting("email_code_limit_ip_window_minutes", request.form.get("email_code_limit_ip_window_minutes", "10"))
    set_setting("email_code_limit_session_count", request.form.get("email_code_limit_session_count", "3"))
    set_setting("email_code_limit_session_window_minutes", request.form.get("email_code_limit_session_window_minutes", "10"))
    set_setting("download_limit_count", request.form.get("download_limit_count", "5"))
    set_setting("download_limit_window_seconds", request.form.get("download_limit_window_seconds", "60"))
    set_setting("multithread_window_seconds", request.form.get("multithread_window_seconds", "10"))
    set_setting("multithread_threshold", request.form.get("multithread_threshold", "3"))
    set_setting("multithread_tag_expire_minutes", request.form.get("multithread_tag_expire_minutes", "10"))
    set_setting("multithread_disable_threshold", request.form.get("multithread_disable_threshold", "3"))
    set_setting("multithread_disable_minutes", request.form.get("multithread_disable_minutes", "60"))
    set_setting("multithread_disable_mode", request.form.get("multithread_disable_mode", "temporary"))
    log_action("admin_update_settings", "registration_settings", actor_user_id=user["id"])
    flash("注册设置已更新。")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/site-settings", methods=["POST"])
def admin_site_settings():
    user = get_current_user()
    require_admin(user)
    site_title = request.form.get("site_title", "").strip()
    site_subtitle = request.form.get("site_subtitle", "").strip()
    site_icon_path = request.form.get("site_icon_path", "").strip()
    if site_icon_path and not (
        site_icon_path.startswith("http://")
        or site_icon_path.startswith("https://")
        or Path(site_icon_path).is_absolute()
    ):
        flash("网站图标路径需要填写绝对路径。")
        return redirect(url_for("admin_dashboard"))
    set_setting("site_title", site_title or "Minecraft 地图展示")
    set_setting("site_subtitle", site_subtitle)
    set_setting("site_icon_path", site_icon_path)
    log_action("admin_update_site", "site_settings", actor_user_id=user["id"])
    flash("站点显示设置已更新。")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/maps/scan", methods=["POST"])
def admin_scan_maps():
    user = get_current_user()
    require_admin(user)
    refresh_map_cache()
    log_action("admin_scan_maps", None, actor_user_id=user["id"])
    flash("地图列表已重新扫描。")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/debug")
def admin_debug():
    user = get_current_user()
    require_admin(user)
    if not CONFIG.get("debug", False):
        abort(404)
    maps, last_scan_at = get_cached_maps()
    maps_serialized = [
        {
            "name": item["name"],
            "zip_path": str(item["zip_path"]),
            "detail_url": item.get("detail_url"),
        }
        for item in maps
    ]
    with get_db() as conn:
        settings = conn.execute("SELECT * FROM settings ORDER BY key").fetchall()
    debug_info = {
        "config": make_json_safe(CONFIG),
        "base_dir": str(BASE_DIR),
        "db_path": str(DB_PATH),
        "mcmap_dir": str(MCMAP_DIR),
        "last_scan_at": make_json_safe(last_scan_at),
        "cached_maps": maps_serialized,
        "map_dir_entries": list_directory(MCMAP_DIR),
        "base_dir_entries": list_directory(BASE_DIR),
        "settings": [make_json_safe(row) for row in settings],
        "flask_config": make_json_safe(dict(app.config)),
    }
    return render_template("admin_debug.html", user=user, debug_info=debug_info)


@app.route("/admin/users")
def admin_users():
    user = get_current_user()
    require_admin(user)
    with get_db() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        admin_count = conn.execute("SELECT COUNT(*) AS count FROM users WHERE role='admin'").fetchone()[
            "count"
        ]
    user_flags = {}
    for account in users:
        cleanup_user_flags(account["id"])
        user_flags[account["id"]] = get_user_flags(account["id"])
    return render_template(
        "admin_users.html",
        user=user,
        users=users,
        admin_count=admin_count,
        user_flags=user_flags,
    )


@app.route("/admin/users/add", methods=["POST"])
def admin_add_user():
    user = get_current_user()
    require_admin(user)
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")
    email = request.form.get("email", "").strip()
    enabled = 1 if request.form.get("enabled") == "on" else 0
    email_verified = 1 if request.form.get("email_verified") == "on" else 0
    if role not in {"user", "admin"}:
        flash("角色无效。")
        return redirect(url_for("admin_users"))
    if not username or not password:
        flash("请填写用户名和密码。")
        return redirect(url_for("admin_users"))
    try:
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, role, enabled, created_at, email, email_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    generate_password_hash(password),
                    role,
                    enabled,
                    datetime.utcnow().isoformat(),
                    email if email else None,
                    email_verified,
                ),
            )
        log_action("admin_create_user", f"username={username}", actor_user_id=user["id"])
        flash("用户已创建。")
    except sqlite3.IntegrityError:
        flash("用户名已存在。")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
def admin_toggle_user(user_id):
    user = get_current_user()
    require_admin(user)
    with get_db() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            abort(404)
        admin_count = conn.execute("SELECT COUNT(*) AS count FROM users WHERE role='admin'").fetchone()[
            "count"
        ]
        if target["role"] == "admin" and target["enabled"] and admin_count <= 1:
            flash("至少需要保留一个启用状态的管理员。")
            return redirect(url_for("admin_users"))
        new_status = 0 if target["enabled"] else 1
        conn.execute("UPDATE users SET enabled=?, disabled_until=NULL WHERE id=?", (new_status, user_id))
    log_action("admin_toggle_user", f"user_id={user_id},enabled={new_status}", actor_user_id=user["id"])
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
def admin_set_role(user_id):
    user = get_current_user()
    require_admin(user)
    new_role = request.form.get("role", "user")
    if new_role not in {"user", "admin"}:
        abort(400)
    with get_db() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            abort(404)
        if target["role"] == "admin" and new_role != "admin":
            admin_count = conn.execute("SELECT COUNT(*) AS count FROM users WHERE role='admin'").fetchone()[
                "count"
            ]
            if admin_count <= 1:
                flash("至少需要保留一个管理员。")
                return redirect(url_for("admin_users"))
        conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    log_action("admin_set_role", f"user_id={user_id},role={new_role}", actor_user_id=user["id"])
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_delete_user(user_id):
    user = get_current_user()
    require_admin(user)
    with get_db() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            abort(404)
        if target["role"] == "admin":
            admin_count = conn.execute("SELECT COUNT(*) AS count FROM users WHERE role='admin'").fetchone()[
                "count"
            ]
            if admin_count <= 1:
                flash("至少需要保留一个管理员。")
                return redirect(url_for("admin_users"))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    log_action("admin_delete_user", f"user_id={user_id}", actor_user_id=user["id"])
    return redirect(url_for("admin_users"))


@app.route("/admin/tags", methods=["GET", "POST"])
def admin_tags():
    user = get_current_user()
    require_admin(user)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        is_global = 1 if request.form.get("is_global") == "on" else 0
        color = request.form.get("color", "").strip()
        if not name:
            flash("标签名不能为空。")
        else:
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO tags (name, is_global, color, created_at) VALUES (?, ?, ?, ?)",
                        (name, is_global, color or None, datetime.utcnow().isoformat()),
                    )
                flash("标签创建成功。")
            except sqlite3.IntegrityError:
                flash("标签已存在。")
    with get_db() as conn:
        tags = conn.execute("SELECT * FROM tags ORDER BY created_at DESC").fetchall()
    return render_template("admin_tags.html", user=user, tags=tags)


@app.route("/admin/tags/new", methods=["GET", "POST"])
def admin_tags_new():
    user = get_current_user()
    require_admin(user)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        is_global = 1 if request.form.get("is_global") == "on" else 0
        color = request.form.get("color", "").strip()
        if not name:
            flash("标签名不能为空。")
        else:
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO tags (name, is_global, color, created_at) VALUES (?, ?, ?, ?)",
                        (name, is_global, color or None, datetime.utcnow().isoformat()),
                    )
                flash("标签创建成功，可关闭窗口。")
            except sqlite3.IntegrityError:
                flash("标签已存在。")
    return render_template("admin_tags_new.html", user=user)


@app.route("/admin/tags/<int:tag_id>/toggle", methods=["POST"])
def admin_toggle_tag(tag_id):
    user = get_current_user()
    require_admin(user)
    with get_db() as conn:
        tag = conn.execute("SELECT * FROM tags WHERE id=?", (tag_id,)).fetchone()
        if not tag:
            abort(404)
        new_value = 0 if tag["is_global"] else 1
        conn.execute("UPDATE tags SET is_global=? WHERE id=?", (new_value, tag_id))
    return redirect(url_for("admin_tags"))


@app.route("/admin/tags/<int:tag_id>/delete", methods=["POST"])
def admin_delete_tag(tag_id):
    user = get_current_user()
    require_admin(user)
    with get_db() as conn:
        conn.execute("DELETE FROM map_tags WHERE tag_id=?", (tag_id,))
        conn.execute("DELETE FROM tags WHERE id=?", (tag_id,))
    return redirect(url_for("admin_tags"))


@app.route("/admin/maps/<map_name>/edit", methods=["GET", "POST"])
def admin_edit_map(map_name):
    user = get_current_user()
    require_admin(user)
    maps, _ = get_cached_maps()
    maps = {item["name"]: item for item in maps}
    if map_name not in maps:
        abort(404)
    with get_db() as conn:
        tags = conn.execute(
            """
            SELECT * FROM tags
            WHERE is_global=1
               OR id IN (SELECT tag_id FROM map_tags WHERE map_name=?)
            ORDER BY name
            """,
            (map_name,),
        ).fetchall()
        current_tags = conn.execute(
            "SELECT tag_id FROM map_tags WHERE map_name=?",
            (map_name,),
        ).fetchall()
    current_ids = {row["tag_id"] for row in current_tags}

    if request.method == "POST":
        action = request.form.get("action", "update")
        if action == "create_tag":
            name = request.form.get("new_tag_name", "").strip()
            is_global = 1 if request.form.get("new_tag_global") == "on" else 0
            color = request.form.get("new_tag_color", "").strip()
            if not name:
                flash("标签名不能为空。")
            else:
                try:
                    with get_db() as conn:
                        conn.execute(
                            "INSERT INTO tags (name, is_global, color, created_at) VALUES (?, ?, ?, ?)",
                            (name, is_global, color or None, datetime.utcnow().isoformat()),
                        )
                        if not is_global:
                            tag_row = conn.execute(
                                "SELECT id FROM tags WHERE name=?",
                                (name,),
                            ).fetchone()
                            if tag_row:
                                conn.execute(
                                    "INSERT INTO map_tags (map_name, tag_id) VALUES (?, ?)",
                                    (map_name, tag_row["id"]),
                                )
                    flash("标签创建成功。")
                except sqlite3.IntegrityError:
                    flash("标签已存在。")
            return redirect(url_for("admin_edit_map", map_name=map_name))

        selected = request.form.getlist("tags")
        selected_ids = {int(tag_id) for tag_id in selected}
        description = request.form.get("description", "").strip()
        display_name = request.form.get("display_name", "").strip()
        version = request.form.get("version", "").strip()
        with get_db() as conn:
            conn.execute("DELETE FROM map_tags WHERE map_name=?", (map_name,))
            for tag_id in selected_ids:
                conn.execute(
                    "INSERT INTO map_tags (map_name, tag_id) VALUES (?, ?)",
                    (map_name, tag_id),
                )
            conn.execute(
                """
                INSERT INTO map_descriptions (map_name, description, updated_at, display_name, version)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(map_name) DO UPDATE SET
                    description=excluded.description,
                    updated_at=excluded.updated_at,
                    display_name=excluded.display_name,
                    version=excluded.version
                """,
                (map_name, description, datetime.utcnow().isoformat(), display_name, version),
            )
        flash("标签与简介已更新。")
        return redirect(url_for("admin_edit_map", map_name=map_name))

    default_tags = get_global_tags()
    metadata = get_map_metadata(map_name)
    return render_template(
        "admin_edit_map.html",
        user=user,
        map_name=map_name,
        tags=tags,
        current_ids=current_ids,
        default_tags=default_tags,
        description=metadata["description"],
        display_name=metadata["display_name"],
        version=metadata["version"],
    )


@app.route("/admin/downloads")
def admin_downloads():
    user = get_current_user()
    require_admin(user)
    with get_db() as conn:
        downloads = conn.execute(
            """
            SELECT downloads.*, users.username
            FROM downloads
            JOIN users ON downloads.user_id = users.id
            ORDER BY downloads.downloaded_at DESC
            """
        ).fetchall()
    return render_template("admin_downloads.html", user=user, downloads=downloads)


@app.route("/admin/logs")
def admin_logs():
    user = get_current_user()
    require_admin(user)
    with get_db() as conn:
        logs = conn.execute(
            """
            SELECT operation_logs.*, users.username
            FROM operation_logs
            LEFT JOIN users ON operation_logs.actor_user_id = users.id
            ORDER BY operation_logs.created_at DESC
            LIMIT 200
            """
        ).fetchall()
    return render_template("admin_logs.html", user=user, logs=logs)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
