"""
Веб-приложение: Flask + сессии в cookie.

Ключевой принцип безопасности: браузер присылает только НАМЕРЕНИЕ
(игра, сумма, параметры ставки). Сумму выигрыша, исход и баланс
считает исключительно сервер. Всё, что пришло от клиента, — недоверенные данные.
"""

import os
import secrets
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

import db
import games
import telegram_auth

app = Flask(__name__)
# В проде ключ берётся из переменной окружения и никогда не лежит в коде.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # cookie недоступна для JavaScript
    SESSION_COOKIE_SAMESITE="Lax",  # защита от CSRF со сторонних сайтов
)

MIN_BET_CENTS = 10
MAX_BET_CENTS = 50_000

TOPUP_CENTS = 100_000        # 1000 фишек за одно пополнение
TOPUP_COOLDOWN_SECONDS = 60  # не чаще раза в минуту, иначе кнопка бессмысленна

# Токен берётся из переменной окружения, а не из кода: тот, кто увидит
# исходники (например, на GitHub), не должен получить возможность
# подписывать поддельные данные от имени вашего бота.
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify(error="Требуется вход"), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


# ------------------------------------------------------- Страницы ----


@app.route("/")
@login_required
def index():
    return render_template("index.html", user=db.get_user(session["user_id"]))


@app.route("/tg")
def telegram_entry():
    """
    URL, который указывается в @BotFather как адрес Mini App.
    Показывает пустой экран загрузки, пока telegram-entry.js не подтвердит
    личность через /api/telegram-login и не перекинет на обычную "/".
    """
    return render_template("telegram_entry.html")


@app.post("/api/telegram-login")
def api_telegram_login():
    if not TELEGRAM_BOT_TOKEN:
        return jsonify(error="Бот не настроен на сервере (нет TELEGRAM_BOT_TOKEN)"), 500

    init_data = (request.get_json(silent=True) or {}).get("initData", "")
    tg_user = telegram_auth.validate_init_data(init_data, TELEGRAM_BOT_TOKEN)
    if not tg_user or "id" not in tg_user:
        return jsonify(error="Не удалось подтвердить личность Telegram"), 401

    display_name = tg_user.get("username") or tg_user.get("first_name") or f"Игрок {tg_user['id']}"
    seed = games.new_server_seed()
    user_id = db.get_or_create_telegram_user(
        tg_user["id"], display_name, seed, games.seed_hash(seed)
    )
    session.clear()
    session["user_id"] = user_id
    return jsonify(ok=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = db.get_user_by_name(request.form.get("username", "").strip())
        if user and db.verify_password(request.form.get("password", ""), user["password_hash"]):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))
        # Намеренно не уточняем, логин неверен или пароль:
        # иначе форма превращается в проверялку существующих аккаунтов.
        return render_template("login.html", error="Неверный логин или пароль"), 401
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(password) < 8:
            return render_template(
                "login.html", register=True,
                error="Логин от 3 символов, пароль от 8"), 400
        if db.get_user_by_name(username):
            return render_template(
                "login.html", register=True, error="Логин занят"), 400

        seed = games.new_server_seed()
        user_id = db.create_user(username, password, seed, games.seed_hash(seed))
        session.clear()
        session["user_id"] = user_id
        return redirect(url_for("index"))
    return render_template("login.html", register=True)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------ API ----


@app.get("/api/me")
@login_required
def api_me():
    u = db.get_user(session["user_id"])
    return jsonify(
        username=u["username"],
        balance=u["balance_cents"] / 100,
        client_seed=u["client_seed"],
        server_seed_hash=u["server_seed_hash"],
        nonce=u["nonce"],
    )


@app.post("/api/bet")
@login_required
def api_bet():
    data = request.get_json(silent=True) or {}
    game = data.get("game")
    if game not in games.ROLLS_NEEDED:
        return jsonify(error="Неизвестная игра"), 400

    # Сумма приходит в фишках, внутри живёт в целых копейках.
    try:
        bet_cents = int(round(float(data.get("bet", 0)) * 100))
    except (TypeError, ValueError):
        return jsonify(error="Некорректная ставка"), 400
    if not MIN_BET_CENTS <= bet_cents <= MAX_BET_CENTS:
        return jsonify(error=f"Ставка от {MIN_BET_CENTS/100} до {MAX_BET_CENTS/100} фишек"), 400

    u = db.get_user(session["user_id"])
    if u["balance_cents"] < bet_cents:
        return jsonify(error="Недостаточно фишек"), 400

    outcome = games.play(
        game, u["server_seed"], u["client_seed"], u["nonce"], data.get("params", {})
    )
    payout_cents = int(bet_cents * outcome["multiplier"])

    try:
        new_balance = db.settle_bet(
            u["id"], game, bet_cents, payout_cents, outcome["text"],
            {"server_seed_hash": u["server_seed_hash"],
             "client_seed": u["client_seed"], "nonce": u["nonce"]},
        )
    except ValueError as e:
        return jsonify(error=str(e)), 400

    return jsonify(
        **outcome,
        payout=payout_cents / 100,
        profit=(payout_cents - bet_cents) / 100,
        balance=new_balance / 100,
        nonce=u["nonce"],
    )


@app.post("/api/topup")
@login_required
def api_topup():
    """
    Бесплатное пополнение виртуальными фишками. Никаких денег здесь нет —
    это игровая валюта без реальной стоимости, поэтому платёжный шлюз не нужен.
    """
    result = db.topup(session["user_id"], TOPUP_CENTS, TOPUP_COOLDOWN_SECONDS)
    if not result["ok"]:
        return jsonify(error="Пополнение доступно раз в минуту",
                        wait_seconds=result["wait_seconds"]), 429
    return jsonify(balance=result["balance_cents"] / 100, added=TOPUP_CENTS / 100)


@app.get("/api/history")
@login_required
def api_history():
    rows = db.history(session["user_id"])
    return jsonify([
        {"game": r["game"], "bet": r["bet_cents"] / 100,
         "profit": (r["payout_cents"] - r["bet_cents"]) / 100,
         "result": r["result_text"], "nonce": r["nonce"], "at": r["created_at"]}
        for r in rows
    ])


@app.post("/api/seed/client")
@login_required
def api_client_seed():
    seed = (request.get_json(silent=True) or {}).get("client_seed", "").strip()
    if not 1 <= len(seed) <= 64:
        return jsonify(error="Сид от 1 до 64 символов"), 400
    db.set_client_seed(session["user_id"], seed)
    return jsonify(client_seed=seed)


@app.post("/api/seed/rotate")
@login_required
def api_rotate():
    """Раскрывает старый server_seed — теперь прошлые ставки можно перепроверить."""
    new_seed = games.new_server_seed()
    revealed = db.rotate_seed(session["user_id"], new_seed, games.seed_hash(new_seed))
    return jsonify(
        revealed_server_seed=revealed,
        revealed_hash=games.seed_hash(revealed),
        new_server_seed_hash=games.seed_hash(new_seed),
    )


if __name__ == "__main__":
    db.init()
    app.run(debug=True, port=5000)
