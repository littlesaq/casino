"""
Проверка initData — строки, которую Telegram передаёт Mini App при открытии.

Без проверки подписи любой мог бы открыть сайт напрямую в браузере,
подделать JSON вида {"id": 12345, ...} и войти под чужим telegram_id.
Telegram подписывает данные секретом бота, поэтому подделать подпись,
не зная токен бота, невозможно.

Алгоритм — ровно тот, что описан в официальной документации Telegram
(Validating data received via the Mini App).
"""

import hashlib
import hmac
import json
import time
from urllib.parse import parse_qsl


def validate_init_data(init_data: str, bot_token: str, max_age_seconds: int = 86400) -> dict | None:
    """
    Возвращает словарь пользователя Telegram, если подпись верна и данные
    не устарели. Возвращает None при любой попытке подделки или просрочке.
    """
    if not init_data or not bot_token:
        return None

    try:
        pairs = dict(parse_qsl(init_data, strict_parsing=True))
    except ValueError:
        return None

    received_hash = pairs.pop("hash", None)
    if not received_hash:
        return None

    # Строка для проверки — все поля, кроме hash, отсортированные по ключу.
    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))

    # Секретный ключ = HMAC-SHA256("WebAppData", bot_token) — так требует Telegram.
    secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    # compare_digest — сравнение за постоянное время, чтобы длина совпадения
    # не утекала через тайминг ответа.
    if not hmac.compare_digest(computed_hash, received_hash):
        return None

    auth_date = int(pairs.get("auth_date", 0))
    if time.time() - auth_date > max_age_seconds:
        return None  # старую ссылку могли перехватить и переиспользовать позже

    try:
        return json.loads(pairs.get("user", "{}"))
    except json.JSONDecodeError:
        return None
