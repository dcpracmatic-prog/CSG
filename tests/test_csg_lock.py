"""Tests de la cerradura Python (csg_lock.py) — unittest, sin dependencias extra.

Cubre los tres arreglos de 2026-11-11:
  1. pickle no filtra la dirección (Q3 estructural),
  2. AES-256-GCM en vez de XOR repetitivo (cifrado con autenticación),
  3. conatus como retardo real medido en segundos.

Ejecutar:  python3 -m unittest discover -s tests -v
"""
import pickle
import sys
import time
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from csg_lock import (  # noqa: E402
    BlindLock,
    aesgcm_decrypt,
    aesgcm_encrypt,
    random_direction,
)
from cryptography.exceptions import InvalidTag  # noqa: E402


def make_lock(payload=b"secreto de prueba"):
    """Enrola y devuelve (lock, direccion_del_dueño guardada FUERA del token)."""
    direction = random_direction()
    lock = BlindLock()
    lock.enroll(payload, direction=direction)
    return lock, direction


class TestPickleNoFiltraDireccion(unittest.TestCase):
    def test_pickle_no_contiene_la_direccion(self):
        lock, direction = make_lock()
        blob = pickle.dumps(lock)
        self.assertNotIn(direction.tobytes(), blob,
                         "pickle.dumps(lock) todavía recupera true_direction")
        recovered = pickle.loads(blob)
        self.assertIsNone(recovered.true_direction)
        # Y el token recuperado sigue verificando con la dirección del dueño.
        result = recovered.attempt_access(direction)
        self.assertTrue(result["granted"])
        self.assertEqual(result["payload"], b"secreto de prueba")

    def test_pickle_no_filtra_tras_fallos(self):
        # Con damage_log lleno el blob es mayor; la dirección tampoco aparece.
        lock, direction = make_lock()
        for _ in range(5):
            lock.attempt_access(random_direction())
        self.assertTrue(lock.structure_broken)
        blob = pickle.dumps(lock)
        self.assertNotIn(direction.tobytes(), blob)
        self.assertIsNone(pickle.loads(blob).true_direction)

    def test_enroll_no_conserva_la_direccion(self):
        lock, _ = make_lock()
        self.assertIsNone(lock.true_direction)


class TestAesGcm(unittest.TestCase):
    def test_roundtrip(self):
        key = bytes(range(32))
        self.assertEqual(aesgcm_decrypt(aesgcm_encrypt(b"hola", key), key), b"hola")

    def test_sin_repeticion_de_flujo(self):
        # El defecto del XOR: el cifrado de 96 B de 'A' repetía cada 32 B.
        key = b"K" * 32
        ct = aesgcm_encrypt(b"A" * 96, key)
        body = ct[12:]  # sin nonce
        self.assertNotEqual(body[0:32], body[32:64])
        self.assertNotEqual(body[32:64], body[64:96])

    def test_mismo_claro_nunca_repite_cifrado(self):
        key = b"K" * 32
        self.assertNotEqual(aesgcm_encrypt(b"mismo", key),
                            aesgcm_encrypt(b"mismo", key))

    def test_alteracion_de_un_bit_se_detecta(self):
        key = b"K" * 32
        blob = bytearray(aesgcm_encrypt(b"secreto", key))
        blob[-1] ^= 0x01
        with self.assertRaises(InvalidTag):
            aesgcm_decrypt(bytes(blob), key)


class TestConatusRetardoReal(unittest.TestCase):
    def test_conatus_es_retardo_real(self):
        lock, _ = make_lock()
        t0 = time.perf_counter()
        for _ in range(3):
            lock.attempt_access(random_direction())
        elapsed = time.perf_counter() - t0
        # Sleeps esperados: 0.05*(1.6+2.56+4.096) = 0.4128 s.
        # Se exige >= 80% para tolerar carga del sistema (el sleep no acorta).
        expected = 0.05 * (1.6 + 2.56 + 4.096)
        self.assertGreaterEqual(elapsed, 0.8 * expected,
                                f"3 fallos tardaron {elapsed:.3f}s, "
                                f"esperado >= {0.8 * expected:.3f}s de retardo conatus")
        self.assertAlmostEqual(lock.conatus_level, 4.096, places=3)

    def test_exito_no_espera(self):
        # Base de retardo exagerada (5 s): si el éxito durmiera, tardaría
        # 5 s; como no es un evento de daño, solo paga el PBKDF2 (~0.15 s).
        lock, direction = make_lock()
        lock.conatus_delay_base_s = 5.0
        t0 = time.perf_counter()
        result = lock.attempt_access(direction)
        elapsed = time.perf_counter() - t0
        self.assertTrue(result["granted"])
        self.assertEqual(lock.conatus_level, 1.0)
        self.assertLess(elapsed, 1.0, "el acceso legítimo no debe pagar retardo")


class TestRupturaSigueIntacta(unittest.TestCase):
    def test_cinco_fallos_rompen_y_dueno_queda_fuera(self):
        lock, direction = make_lock(b"PLANO")
        for _ in range(5):
            result = lock.attempt_access(random_direction())
        self.assertTrue(result["structure_broken"])
        self.assertEqual(len(lock.damage_log), 5)
        self.assertAlmostEqual(lock.conatus_level, 1.6 ** 5, places=3)
        self.assertFalse(lock.attempt_access(direction)["granted"])


if __name__ == "__main__":
    unittest.main()
