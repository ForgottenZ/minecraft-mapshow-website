import os
import sqlite3
from datetime import datetime
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
MCMAP_DIR = BASE_DIR / "mcmap"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")


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
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS map_tags (
                map_name TEXT NOT NULL,
                tag_id INTEGER NOT NULL,
                PRIMARY KEY (map_name, tag_id),
                FOREIGN KEY(tag_id) REFERENCES tags(id)
            );
            """
        )


def has_admin():
    with get_db() as conn:
        row = conn.execute("SELECT COUNT(*) AS count FROM users WHERE role='admin'").fetchone()
    return row["count"] > 0


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def require_admin(user):
    if not user or user["role"] != "admin" or not user["enabled"]:
        abort(403)


def load_maps():
    maps = []
    if not MCMAP_DIR.exists():
        return maps

    for entry in sorted(MCMAP_DIR.iterdir()):
        if not entry.is_dir():
            continue
        map_name = entry.name
        zip_path = MCMAP_DIR / f"{map_name}.zip"
        if not zip_path.exists():
            continue

        url_file = None
        for candidate in MCMAP_DIR.glob("*.url"):
            stem = candidate.stem
            if stem == map_name or stem.startswith(map_name):
                url_file = candidate
                break
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


def get_default_tags():
    with get_db() as conn:
        return conn.execute("SELECT * FROM tags WHERE is_default=1 ORDER BY name").fetchall()


@app.before_request
def ensure_setup():
    init_db()
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
        if not user or not check_password_hash(user["password_hash"], password):
            flash("用户名或密码错误。")
        elif not user["enabled"]:
            flash("该账号已被禁用。")
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
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("请填写用户名和密码。")
        else:
            try:
                with get_db() as conn:
                    conn.execute(
                        """
                        INSERT INTO users (username, password_hash, role, enabled, created_at)
                        VALUES (?, ?, 'user', 1, ?)
                        """,
                        (username, generate_password_hash(password), datetime.utcnow().isoformat()),
                    )
                flash("注册成功，请登录。")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("用户名已存在。")
    return render_template("register.html")


@app.route("/")
def index():
    user = get_current_user()
    maps = load_maps()
    map_items = []
    for item in maps:
        map_items.append(
            {
                **item,
                "tags": get_map_tags(item["name"]),
            }
        )
    return render_template(
        "maps.html",
        user=user,
        maps=map_items,
    )


@app.route("/maps/<map_name>")
def map_detail(map_name):
    user = get_current_user()
    maps = {item["name"]: item for item in load_maps()}
    if map_name not in maps:
        abort(404)
    item = maps[map_name]
    tags = get_map_tags(map_name)
    return render_template(
        "map_detail.html",
        user=user,
        map_item=item,
        tags=tags,
    )


@app.route("/download/<map_name>")
def download(map_name):
    user = get_current_user()
    if not user or not user["enabled"]:
        flash("请先登录后下载。")
        return redirect(url_for("login"))
    maps = {item["name"]: item for item in load_maps()}
    if map_name not in maps:
        abort(404)
    zip_path = maps[map_name]["zip_path"]
    with get_db() as conn:
        conn.execute(
            "INSERT INTO downloads (user_id, map_name, downloaded_at) VALUES (?, ?, ?)",
            (user["id"], map_name, datetime.utcnow().isoformat()),
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
    return render_template(
        "admin_dashboard.html",
        user=user,
        user_count=user_count,
        download_count=download_count,
        tag_count=tag_count,
    )


@app.route("/admin/users")
def admin_users():
    user = get_current_user()
    require_admin(user)
    with get_db() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        admin_count = conn.execute("SELECT COUNT(*) AS count FROM users WHERE role='admin'").fetchone()[
            "count"
        ]
    return render_template("admin_users.html", user=user, users=users, admin_count=admin_count)


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
        conn.execute("UPDATE users SET enabled=? WHERE id=?", (new_status, user_id))
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
    return redirect(url_for("admin_users"))


@app.route("/admin/tags", methods=["GET", "POST"])
def admin_tags():
    user = get_current_user()
    require_admin(user)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        is_default = 1 if request.form.get("is_default") == "on" else 0
        if not name:
            flash("标签名不能为空。")
        else:
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO tags (name, is_default, created_at) VALUES (?, ?, ?)",
                        (name, is_default, datetime.utcnow().isoformat()),
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
        is_default = 1 if request.form.get("is_default") == "on" else 0
        if not name:
            flash("标签名不能为空。")
        else:
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO tags (name, is_default, created_at) VALUES (?, ?, ?)",
                        (name, is_default, datetime.utcnow().isoformat()),
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
        new_value = 0 if tag["is_default"] else 1
        conn.execute("UPDATE tags SET is_default=? WHERE id=?", (new_value, tag_id))
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
    maps = {item["name"]: item for item in load_maps()}
    if map_name not in maps:
        abort(404)
    with get_db() as conn:
        tags = conn.execute("SELECT * FROM tags ORDER BY name").fetchall()
        current_tags = conn.execute(
            "SELECT tag_id FROM map_tags WHERE map_name=?",
            (map_name,),
        ).fetchall()
    current_ids = {row["tag_id"] for row in current_tags}

    if request.method == "POST":
        selected = request.form.getlist("tags")
        selected_ids = {int(tag_id) for tag_id in selected}
        with get_db() as conn:
            conn.execute("DELETE FROM map_tags WHERE map_name=?", (map_name,))
            for tag_id in selected_ids:
                conn.execute(
                    "INSERT INTO map_tags (map_name, tag_id) VALUES (?, ?)",
                    (map_name, tag_id),
                )
        flash("标签已更新。")
        return redirect(url_for("admin_edit_map", map_name=map_name))

    default_tags = get_default_tags()
    return render_template(
        "admin_edit_map.html",
        user=user,
        map_name=map_name,
        tags=tags,
        current_ids=current_ids,
        default_tags=default_tags,
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
