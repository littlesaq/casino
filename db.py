"""
Слой базы данных. Чистый sqlite3 из стандартной библиотеки — без ORM.

Два правила, на которых держится честность учёта:
1. Баланс хранится в ЦЕЛЫХ (фишки * 100). Никаких float у денег.
2. Списание ставки и начисление выигрыша идут в ОДНОЙ транзакции
   с BEGIN IMMEDIATE, иначе два параллельных запроса смогут потратить
   один и тот же баланс дважды.
"""

import sqlite3
import hashlib
import secrets
from pathlib import Path

DB_PATH = Path(__file__).parent / "casino.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT UNIQUE NOT NULL,
    password_hash    TEXT NOT NULL,
    display_name     TEXT,
    telegram_id      INTEGER,
    balance_cents    INTEGER NOT NULL DEFAULT 100000,
    client_seed      TEXT NOT NULL,
    server_seed      TEXT NOT NULL,
    server_seed_hash TEXT NOT NULL,
    nonce            INTEGER NOT NULL DEFAULT 0,
    last_topup_at    TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_telegram
    ON users(telegram_id) WHERE telegram_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS bets (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL REFERENCES users(id),
    game             TEXT NOT NULL,
    bet_cents        INTEGER NOT NULL,
    payout_cents     INTEGER NOT NULL,
    result_text      TEXT NOT NULL,
    server_seed_hash TEXT NOT NULL,
    client_seed      TEXT NOT NULL,
    nonce            INTEGER NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_bets_user ON bets(user_id, id DESC);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # параллельное чтение при записи
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        # Миграции для баз, созданных до появления новых возможностей.
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        if "last_topup_at" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN last_topup_at TEXT")
        if "telegram_id" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN telegram_id INTEGER")
            conn.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS idx_users_telegram
                   ON users(telegram_id) WHERE telegram_id IS NOT NULL"""
            )
        if "display_name" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT")


# ------------------------------------------------------------ Пароли ----


def hash_password(password: str) -> str:
    """scrypt: медленный по задумке, поэтому перебор дорог. Соль у каждого своя."""
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"{salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, key_hex = stored.split("$")
    except ValueError:
        return False
    key = hashlib.scrypt(
        password.encode(), salt=bytes.fromhex(salt_hex), n=2 ** 14, r=8, p=1, dklen=32
    )
    return secrets.compare_digest(key.hex(), key_hex)


# --------------------------------------------------------- Операции ----


def create_user(username: str, password: str, server_seed: str, seed_hash: str) -> int:
    with connect() as conn:
        cur = conn.execute(
            """INSERT INTO users (username, password_hash, client_seed,
                                  server_seed, server_seed_hash)
               VALUES (?, ?, ?, ?, ?)""",
            (username, hash_password(password), secrets.token_hex(8), server_seed, seed_hash),
        )
        return cur.lastrowid


def get_user(user_id: int) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_name(username: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def settle_bet(user_id: int, game: str, bet_cents: int, payout_cents: int,
               result_text: str, seeds: dict) -> int:
    """
    Атомарно: проверить баланс -> списать ставку -> начислить выплату ->
    увеличить nonce -> записать ставку в журнал. Всё или ничего.
    Возвращает новый баланс.
    """
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT balance_cents, nonce FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row["balance_cents"] < bet_cents:
            raise ValueError("Недостаточно фишек")

        new_balance = row["balance_cents"] - bet_cents + payout_cents
        conn.execute(
            "UPDATE users SET balance_cents = ?, nonce = nonce + 1 WHERE id = ?",
            (new_balance, user_id),
        )
        conn.execute(
            """INSERT INTO bets (user_id, game, bet_cents, payout_cents, result_text,
                                 server_seed_hash, client_seed, nonce)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, game, bet_cents, payout_cents, result_text,
             seeds["server_seed_hash"], seeds["client_seed"], seeds["nonce"]),
        )
        conn.execute("COMMIT")
        return new_balance
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def topup(user_id: int, amount_cents: int, cooldown_seconds: int) -> dict:
    """
    Начисляет бесплатные фишки, если кулдаун истёк. Проверка и списание
    времени — в одной транзакции, иначе два быстрых клика подряд оба
    пройдут проверку "кулдаун истёк" до того, как первый успеет её сбросить.
    """
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT balance_cents, last_topup_at,
                      (julianday('now') - julianday(last_topup_at)) * 86400 AS elapsed
               FROM users WHERE id = ?""",
            (user_id,),
        ).fetchone()

        if row["last_topup_at"] is not None and row["elapsed"] < cooldown_seconds:
            wait = int(cooldown_seconds - row["elapsed"]) + 1
            conn.execute("ROLLBACK")
            return {"ok": False, "wait_seconds": wait}

        new_balance = row["balance_cents"] + amount_cents
        conn.execute(
            "UPDATE users SET balance_cents = ?, last_topup_at = datetime('now') WHERE id = ?",
            (new_balance, user_id),
        )
        conn.execute("COMMIT")
        return {"ok": True, "balance_cents": new_balance}
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get_or_create_telegram_user(telegram_id: int, display_name: str,
                                  server_seed: str, seed_hash: str) -> int:
    """
    Находит аккаунт по telegram_id или заводит новый. BEGIN IMMEDIATE нужен,
    иначе быстрый двойной запуск Mini App (двойной тап по кнопке) может
    успеть дважды пройти проверку "аккаунта ещё нет" и создать два аккаунта
    на одного человека вместо одного.
    """
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT id FROM users WHERE telegram_id = ?", (telegram_id,)
        ).fetchone()
        if row:
            conn.execute("COMMIT")
            return row["id"]

        # Пароль этому аккаунту не нужен — вход только через Telegram,
        # но колонка NOT NULL, поэтому кладём туда неиспользуемый секрет.
        unusable_password = hash_password(secrets.token_hex(32))
        cur = conn.execute(
            """INSERT INTO users (username, password_hash, display_name, telegram_id,
                                  client_seed, server_seed, server_seed_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (f"tg_{telegram_id}", unusable_password, display_name, telegram_id,
             secrets.token_hex(8), server_seed, seed_hash),
        )
        conn.execute("COMMIT")
        return cur.lastrowid
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def rotate_seed(user_id: int, new_seed: str, new_hash: str) -> str:
    """Раскрывает старый server_seed и ставит новый. Nonce обнуляется."""
    with connect() as conn:
        old = conn.execute(
            "SELECT server_seed FROM users WHERE id = ?", (user_id,)
        ).fetchone()["server_seed"]
        conn.execute(
            """UPDATE users SET server_seed = ?, server_seed_hash = ?, nonce = 0
               WHERE id = ?""",
            (new_seed, new_hash, user_id),
        )
        return old


def set_client_seed(user_id: int, client_seed: str) -> None:
    with connect() as conn:
        conn.execute("UPDATE users SET client_seed = ? WHERE id = ?", (client_seed, user_id))


def history(user_id: int, limit: int = 25) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM bets WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
