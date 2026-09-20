"""
Игровой движок казино.

Главная идея: сервер не «придумывает» результат в момент ставки.
Результат жёстко определён тройкой (server_seed, client_seed, nonce).
Хэш server_seed игрок видит ЗАРАНЕЕ, сам server_seed — после ротации.
Значит, подменить исход задним числом невозможно: хэш не сойдётся.
"""

import hashlib
import hmac
import secrets

# ---------------------------------------------------------------- RNG ----


def new_server_seed() -> str:
    """32 случайных байта в hex. Источник — CSPRNG операционной системы."""
    return secrets.token_hex(32)


def seed_hash(server_seed: str) -> str:
    """SHA-256 от server_seed. Это публикуется игроку до ставок."""
    return hashlib.sha256(server_seed.encode()).hexdigest()


def _hmac_bytes(server_seed: str, client_seed: str, nonce: int, cursor: int) -> bytes:
    msg = f"{client_seed}:{nonce}:{cursor}".encode()
    return hmac.new(server_seed.encode(), msg, hashlib.sha256).digest()


def floats(server_seed: str, client_seed: str, nonce: int, count: int) -> list[float]:
    """
    Детерминированный поток чисел [0, 1).

    Из каждого HMAC (32 байта) берём по 4 байта -> 8 чисел на блок.
    Байты собираем в целое и делим на 2**32.
    """
    out: list[float] = []
    cursor = 0
    while len(out) < count:
        block = _hmac_bytes(server_seed, client_seed, nonce, cursor)
        for i in range(0, 32, 4):
            n = int.from_bytes(block[i:i + 4], "big")
            out.append(n / 2 ** 32)
            if len(out) == count:
                return out
        cursor += 1
    return out


# -------------------------------------------------------------- Кости ----

DICE_EDGE = 0.01  # преимущество казино: 1%


def play_dice(rolls: list[float], target: float) -> dict:
    """
    Игрок ставит «выпадет меньше target». target от 1.00 до 95.00.
    Шанс выигрыша = target / 100.
    Честный коэффициент = 100 / target, срезаем на 1% -> дом в плюсе.
    """
    target = max(1.0, min(95.0, float(target)))
    roll = round(rolls[0] * 100, 2)
    win = roll < target
    multiplier = round((100.0 / target) * (1 - DICE_EDGE), 4)
    return {
        "win": win,
        "multiplier": multiplier if win else 0.0,
        "roll": roll,
        "target": target,
        "text": f"Выпало {roll:.2f} — нужно меньше {target:.2f}",
    }


# ------------------------------------------------------------ Рулетка ----

RED = {1, 3, 5, 7, 9, 12, 14, 16, 18, 19, 21, 23, 25, 27, 30, 32, 34, 36}


def play_roulette(rolls: list[float], bet_type: str, value: str) -> dict:
    """
    Европейская рулетка: 37 секторов (0-36), один зеро.
    Преимущество казино берётся из самого зеро — 1/37 = 2.70%.
    Никаких искусственных срезов коэффициента здесь не нужно.
    """
    number = int(rolls[0] * 37)  # 0..36
    color = "зеро" if number == 0 else ("красное" if number in RED else "чёрное")

    multiplier = 0.0
    if bet_type == "number" and number == int(value):
        multiplier = 36.0
    elif bet_type == "color" and number != 0 and color == value:
        multiplier = 2.0
    elif bet_type == "parity" and number != 0:
        is_even = number % 2 == 0
        if (value == "even") == is_even:
            multiplier = 2.0
    elif bet_type == "dozen" and number != 0:
        if (number - 1) // 12 == int(value):
            multiplier = 3.0

    return {
        "win": multiplier > 0,
        "multiplier": multiplier,
        "number": number,
        "color": color,
        "text": f"{number} — {color}",
    }


# ------------------------------------------------------------- Слоты ----

# Барабан: чем чаще символ, тем он дешевле. Сумма весов = 100.
REEL = (
    ["🍒"] * 30 + ["🍋"] * 25 + ["🔔"] * 20 + ["🍇"] * 13 + ["⭐"] * 8 + ["7️⃣"] * 4
)

# Таблицы подобраны не на глаз, а из точной формулы (см. slots_rtp).
# Пара платит только за редкие символы, иначе RTP улетает за 100%.
PAYTABLE_THREE = {"🍒": 5, "🍋": 9, "🔔": 16, "🍇": 45, "⭐": 200, "7️⃣": 1200}
PAYTABLE_TWO = {"🍒": 0.5, "🍇": 1.5, "⭐": 4, "7️⃣": 10}


def play_slots(rolls: list[float]) -> dict:
    """Три независимых барабана. Три в ряд — крупно, пара — утешение."""
    reels = [REEL[int(rolls[i] * len(REEL))] for i in range(3)]
    multiplier = 0.0
    text = "Мимо"

    if reels[0] == reels[1] == reels[2]:
        multiplier = float(PAYTABLE_THREE[reels[0]])
        text = f"Три {reels[0]} подряд"
    else:
        for symbol in set(reels):
            if reels.count(symbol) == 2 and symbol in PAYTABLE_TWO:
                multiplier = float(PAYTABLE_TWO[symbol])
                text = f"Пара {symbol}"
                break

    return {
        "win": multiplier > 0,
        "multiplier": multiplier,
        "reels": reels,
        "text": text,
    }


def slots_rtp() -> float:
    """
    Точный RTP без симуляции.
    Вероятность трёх одинаковых = p³, ровно двух = 3·p²·(1−p).
    Меняете таблицу выплат — сразу проверяйте этой функцией.
    """
    total = 0.0
    for symbol in set(REEL):
        p = REEL.count(symbol) / len(REEL)
        total += p ** 3 * PAYTABLE_THREE[symbol]
        total += 3 * p ** 2 * (1 - p) * PAYTABLE_TWO.get(symbol, 0)
    return total


# ------------------------------------------------------- Диспетчер ----

# Сколько случайных чисел нужно каждой игре — фиксировано, чтобы
# проверка результата третьей стороной была однозначной.
ROLLS_NEEDED = {"dice": 1, "roulette": 1, "slots": 3}


def play(game: str, server_seed: str, client_seed: str, nonce: int, params: dict) -> dict:
    rolls = floats(server_seed, client_seed, nonce, ROLLS_NEEDED[game])
    if game == "dice":
        return play_dice(rolls, params.get("target", 50.0))
    if game == "roulette":
        return play_roulette(rolls, params.get("bet_type", "color"), params.get("value", "красное"))
    if game == "slots":
        return play_slots(rolls)
    raise ValueError("неизвестная игра")
