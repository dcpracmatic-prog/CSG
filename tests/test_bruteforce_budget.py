"""Fuerza bruta con presupuesto: 1 millón de direcciones aleatorias en R^64.

No usa attempt_access (que añade PBKDF2 + retardo conatus por intento:
1M intentos tardaría horas) sino verify_blind, la verificación todo-o-nada
que un atacante offline puede correr contra el commit robado. Es el ataque
realista contra el token en disco y el que la frase de fuerza bruta del
README debe acotar.

Ejecutar:  python3 -m unittest tests.test_bruteforce_budget -v
Medido en sandbox 2026-11-11: ~15 s para 1M intentos, 0 aciertos.
"""
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from csg_lock import BlindLock, random_direction, verify_blind  # noqa: E402

BUDGET = 1_000_000


class TestFuerzaBrutaConPresupuesto(unittest.TestCase):
    def test_un_millon_de_direcciones_sin_acierto(self):
        direction = random_direction()
        lock = BlindLock()
        lock.enroll(b"secreto", direction=direction)
        hits = 0
        t0 = time.perf_counter()
        for _ in range(BUDGET):
            if verify_blind(random_direction(), lock.stored_commit, lock.salt):
                hits += 1
        elapsed = time.perf_counter() - t0
        print(f"\n  fuerza bruta: {BUDGET:,} intentos en {elapsed:.1f}s "
              f"({BUDGET / elapsed:,.0f}/s), aciertos={hits}")
        self.assertEqual(hits, 0)


if __name__ == "__main__":
    unittest.main()
