"""
Независимая проверка честности. Запускается отдельно от сервера.

После ротации сида вы знаете server_seed. Подставьте его сюда вместе
с client_seed и номером ставки — и получите ровно тот же исход, который
показало казино. Если не совпало, казино вас обмануло.

    python3 verify.py <server_seed> <client_seed> <nonce> <игра>
"""

import sys
import hashlib

import games


def main() -> None:
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)

    server_seed, client_seed, nonce, game = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

    print(f"SHA-256 серверного сида: {hashlib.sha256(server_seed.encode()).hexdigest()}")
    print("Сверьте эту строку с хэшем, который был опубликован ДО ставки.\n")

    params = {"target": 50.0} if game == "dice" else {"bet_type": "color", "value": "красное"}
    result = games.play(game, server_seed, client_seed, nonce, params)

    print(f"Случайные числа: {games.floats(server_seed, client_seed, nonce, games.ROLLS_NEEDED[game])}")
    print(f"Исход: {result['text']}")


if __name__ == "__main__":
    main()
