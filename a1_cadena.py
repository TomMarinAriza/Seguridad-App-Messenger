"""A1. Cadena de claves simétrica.

Cada mensaje se cifra con una clave propia, derivada con HKDF-SHA256 a partir
de una clave de cadena. Después de derivar la clave de un mensaje, la cadena
avanza en un solo sentido y la clave anterior se descarta. Así, quien robe el
estado actual de la cadena no puede reconstruir las claves de mensajes ya
procesados (forward secrecy a nivel de cadena simétrica).

Toda la criptografía usa la biblioteca estándar ``cryptography``:
HKDF-SHA256 (RFC 5869) para derivar y AES-256-GCM para cifrar.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

LONGITUD_CLAVE = 32  # bytes (AES-256)
LONGITUD_NONCE = 12  # bytes (recomendado para AES-GCM)
INFO_MENSAJE = b"taller-seguridad/A1/clave-mensaje"
INFO_CADENA = b"taller-seguridad/A1/clave-cadena"


class ClaveNoDisponible(Exception):
    """La clave pedida ya fue usada y borrada, o nunca existió."""


def _hkdf(material: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=LONGITUD_CLAVE,
        salt=None,
        info=info,
    ).derive(material)


def derivar_clave(cadena: bytes, indice: int) -> bytes:
    """Deriva la clave del mensaje número ``indice`` a partir de ``cadena``.

    La derivación es determinista: la misma clave de cadena y el mismo índice
    producen siempre la misma clave de 32 bytes. El índice se incluye en el
    parámetro ``info`` de HKDF, de modo que índices distintos dan claves
    independientes.

    Args:
        cadena: clave de cadena de 32 bytes.
        indice: número de mensaje (entero mayor o igual a 0).

    Returns:
        Clave de mensaje de 32 bytes, apta para AES-256-GCM.
    """
    if len(cadena) != LONGITUD_CLAVE:
        raise ValueError("La clave de cadena debe tener 32 bytes")
    if indice < 0:
        raise ValueError("El índice no puede ser negativo")
    return _hkdf(cadena, INFO_MENSAJE + indice.to_bytes(8, "big"))


def avanzar_cadena(cadena: bytes) -> bytes:
    """Calcula la siguiente clave de cadena (paso de un solo sentido).

    HKDF no se puede invertir: conocer la cadena nueva no revela la anterior.

    Args:
        cadena: clave de cadena actual de 32 bytes.

    Returns:
        Nueva clave de cadena de 32 bytes.
    """
    return _hkdf(cadena, INFO_CADENA)


def cifrar(clave: bytes, texto: str) -> bytes:
    """Cifra ``texto`` con AES-256-GCM usando ``clave``.

    Args:
        clave: clave de mensaje de 32 bytes.
        texto: texto plano (se codifica en UTF-8).

    Returns:
        ``nonce || ciphertext || etiqueta``. El nonce de 12 bytes es aleatorio.
    """
    nonce = os.urandom(LONGITUD_NONCE)
    return nonce + AESGCM(clave).encrypt(nonce, texto.encode("utf-8"), None)


def descifrar(clave: bytes, datos: bytes) -> str:
    """Descifra lo producido por :func:`cifrar`.

    Args:
        clave: clave de mensaje de 32 bytes.
        datos: ``nonce || ciphertext || etiqueta``.

    Returns:
        El texto plano original.

    Raises:
        cryptography.exceptions.InvalidTag: si la clave es incorrecta o los
            datos fueron alterados.
    """
    nonce, cuerpo = datos[:LONGITUD_NONCE], datos[LONGITUD_NONCE:]
    return AESGCM(clave).decrypt(nonce, cuerpo, None).decode("utf-8")


class CadenaSimetrica:
    """Cadena de claves que entrega una clave por mensaje y la borra al usarla.

    El emisor y el receptor crean cada uno una ``CadenaSimetrica`` con la misma
    clave inicial (en el taller se simula como un secreto compartido local).
    """

    def __init__(self, clave_inicial: bytes) -> None:
        """Crea la cadena a partir de una clave inicial de 32 bytes."""
        if len(clave_inicial) != LONGITUD_CLAVE:
            raise ValueError("La clave inicial debe tener 32 bytes")
        self._cadena = clave_inicial
        self.indice = 0
        # Claves de mensajes derivadas pero aún no usadas (p. ej. llegaron
        # desordenados). Se borran en cuanto se usan.
        self._pendientes: dict[int, bytes] = {}

    @property
    def estado(self) -> bytes:
        """Clave de cadena actual (lo que robaría un atacante)."""
        return self._cadena

    def _avanzar_hasta(self, indice: int) -> None:
        while self.indice <= indice:
            self._pendientes[self.indice] = derivar_clave(self._cadena, self.indice)
            self._cadena = avanzar_cadena(self._cadena)
            self.indice += 1

    def tomar_clave(self, indice: int) -> bytes:
        """Entrega la clave del mensaje ``indice`` y la borra de la cadena.

        Raises:
            ClaveNoDisponible: si esa clave ya se usó (y por tanto se borró).
        """
        self._avanzar_hasta(indice)
        clave = self._pendientes.pop(indice, None)
        if clave is None:
            raise ClaveNoDisponible(f"La clave del mensaje {indice} ya fue borrada")
        return clave

    def cifrar_siguiente(self, texto: str) -> tuple[int, bytes]:
        """Cifra ``texto`` con la siguiente clave y devuelve ``(indice, datos)``."""
        indice = self.indice
        clave = self.tomar_clave(indice)
        datos = cifrar(clave, texto)
        del clave
        return indice, datos

    def descifrar_mensaje(self, indice: int, datos: bytes) -> str:
        """Descifra el mensaje ``indice``; su clave queda borrada después."""
        clave = self.tomar_clave(indice)
        try:
            return descifrar(clave, datos)
        finally:
            del clave
