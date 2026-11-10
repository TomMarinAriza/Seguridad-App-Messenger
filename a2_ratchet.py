"""A2. Double Ratchet reducido.

Versión simplificada del algoritmo Double Ratchet de Signal (Perrin y
Marlinspike, 2016) para dos participantes en un único proceso en memoria,
sin red ni servidor.

Componentes:

* Ratchet de Diffie-Hellman con X25519: cada cambio de dirección genera un par
  de claves nuevo y mezcla el secreto DH en la clave raíz (KDF_RK con HKDF).
* Ratchet simétrico: cada cadena de envío/recepción deriva una clave por
  mensaje con HMAC-SHA256 (KDF_CK) y avanza en un solo sentido.
* Cifrado autenticado AES-256-GCM. El encabezado (clave pública DH, PN, N) se
  autentica como dato asociado.

Simplificaciones frente a Signal: el secreto inicial se simula con
``os.urandom`` en lugar de X3DH/PQXDH, no hay claves de identidad, no se cifran
los encabezados y no se incluye la capa poscuántica (SPQR).

Toda la criptografía usa la biblioteca estándar ``cryptography``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

MAX_SALTO = 100  # máximo de claves de mensajes saltados que se guardan
INFO_RAIZ = b"taller-seguridad/A2/raiz"
INFO_MENSAJE = b"taller-seguridad/A2/mensaje"


class MensajeRechazado(Exception):
    """El mensaje no se aceptó: alterado, repetido o imposible de descifrar."""


# --------------------------------------------------------------------------
# Funciones de derivación (KDF) y cifrado
# --------------------------------------------------------------------------

def _publica_bytes(privada: X25519PrivateKey) -> bytes:
    return privada.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _dh(privada: X25519PrivateKey, publica: bytes) -> bytes:
    return privada.exchange(X25519PublicKey.from_public_bytes(publica))


def kdf_rk(clave_raiz: bytes, salida_dh: bytes) -> tuple[bytes, bytes]:
    """KDF de la clave raíz: devuelve ``(nueva_raiz, clave_de_cadena)``."""
    salida = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=clave_raiz, info=INFO_RAIZ
    ).derive(salida_dh)
    return salida[:32], salida[32:]


def kdf_ck(clave_cadena: bytes) -> tuple[bytes, bytes]:
    """KDF de cadena: devuelve ``(nueva_cadena, clave_de_mensaje)``."""

    def _hmac(constante: bytes) -> bytes:
        h = hmac.HMAC(clave_cadena, hashes.SHA256())
        h.update(constante)
        return h.finalize()

    return _hmac(b"\x02"), _hmac(b"\x01")


def _cifrar(clave_mensaje: bytes, texto: bytes, datos_asociados: bytes) -> bytes:
    material = HKDF(
        algorithm=hashes.SHA256(), length=44, salt=b"\x00" * 32, info=INFO_MENSAJE
    ).derive(clave_mensaje)
    clave, nonce = material[:32], material[32:]
    return AESGCM(clave).encrypt(nonce, texto, datos_asociados)


def _descifrar(clave_mensaje: bytes, cifrado: bytes, datos_asociados: bytes) -> bytes:
    material = HKDF(
        algorithm=hashes.SHA256(), length=44, salt=b"\x00" * 32, info=INFO_MENSAJE
    ).derive(clave_mensaje)
    clave, nonce = material[:32], material[32:]
    return AESGCM(clave).decrypt(nonce, cifrado, datos_asociados)


# --------------------------------------------------------------------------
# Mensajes
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Encabezado:
    """Clave pública DH del emisor, largo de la cadena anterior (PN) y N."""

    dh: bytes
    pn: int
    n: int

    def a_bytes(self) -> bytes:
        return self.dh + self.pn.to_bytes(4, "big") + self.n.to_bytes(4, "big")


@dataclass(frozen=True)
class Mensaje:
    """Mensaje cifrado tal como viajaría por la red."""

    encabezado: Encabezado
    cifrado: bytes


# --------------------------------------------------------------------------
# Ratchet
# --------------------------------------------------------------------------

class Ratchet:
    """Estado de un participante en una sesión Double Ratchet reducida.

    Uso típico::

        alicia, beto = crear_sesion()
        m = alicia.enviar("hola")
        beto.recibir(m)            # -> "hola"
        beto.cambiar_direccion()   # nuevo par X25519 (opcional: enviar lo hace solo)
        alicia.recibir(beto.enviar("hola, Alicia"))
    """

    def __init__(
        self,
        nombre: str,
        secreto_compartido: bytes,
        par_propio: X25519PrivateKey | None = None,
        publica_remota: bytes | None = None,
        datos_asociados: bytes = b"",
    ) -> None:
        """Crea el estado inicial.

        Args:
            nombre: etiqueta del participante (solo informativa).
            secreto_compartido: 32 bytes acordados de antemano (simula X3DH).
            par_propio: par X25519 inicial del receptor (quien no inicia).
            publica_remota: clave pública del receptor; solo la pasa quien
                inicia la conversación.
            datos_asociados: datos que ambos autentican en cada mensaje.
        """
        self.nombre = nombre
        self._ad = datos_asociados
        self._raiz = secreto_compartido
        self._cks: bytes | None = None
        self._ckr: bytes | None = None
        self._dhr: bytes | None = publica_remota
        self._ns = 0
        self._nr = 0
        self._pn = 0
        self._saltadas: dict[tuple[bytes, int], bytes] = {}
        self._dh_antiguas: set[bytes] = set()
        self._cambio_pendiente = False

        if publica_remota is not None:  # quien inicia
            self._dhs = X25519PrivateKey.generate()
            self._raiz, self._cks = kdf_rk(self._raiz, _dh(self._dhs, publica_remota))
        else:  # quien responde
            if par_propio is None:
                raise ValueError("El receptor necesita su par de claves inicial")
            self._dhs = par_propio

    # ---------------------------------------------------------------- API

    @property
    def publica(self) -> bytes:
        """Clave pública X25519 actual de este participante."""
        return _publica_bytes(self._dhs)

    def cambiar_direccion(self) -> None:
        """Genera un par X25519 nuevo y abre una cadena de envío nueva.

        Se llama cuando el participante pasa de recibir a enviar. Mezcla en la
        clave raíz un secreto DH fresco, lo que da *post-compromise security*.

        Raises:
            RuntimeError: si aún no hay una clave pública nueva del otro lado.
        """
        if not self._cambio_pendiente:
            raise RuntimeError(
                "No hay una clave pública nueva del otro participante; "
                "primero hay que recibir un mensaje suyo"
            )
        self._dhs = X25519PrivateKey.generate()
        self._raiz, self._cks = kdf_rk(self._raiz, _dh(self._dhs, self._dhr))
        self._cambio_pendiente = False

    def enviar(self, texto: str) -> Mensaje:
        """Cifra ``texto`` con la siguiente clave de la cadena de envío."""
        if self._cks is None:
            self.cambiar_direccion()
        self._cks, clave_mensaje = kdf_ck(self._cks)
        encabezado = Encabezado(self.publica, self._pn, self._ns)
        self._ns += 1
        cifrado = _cifrar(
            clave_mensaje, texto.encode("utf-8"), self._ad + encabezado.a_bytes()
        )
        return Mensaje(encabezado, cifrado)

    def recibir(self, mensaje: Mensaje) -> str:
        """Descifra ``mensaje``. Si falla, el estado queda exactamente igual.

        Raises:
            MensajeRechazado: si el mensaje fue alterado, está repetido o no
                se puede descifrar.
        """
        copia = self._copiar_estado()
        try:
            return self._recibir(mensaje)
        except MensajeRechazado:
            self._restaurar_estado(copia)
            raise
        except InvalidTag as error:
            self._restaurar_estado(copia)
            raise MensajeRechazado("integridad: el mensaje fue alterado") from error

    # ------------------------------------------------------------ interno

    def _recibir(self, mensaje: Mensaje) -> str:
        h = mensaje.encabezado
        ad = self._ad + h.a_bytes()

        clave_saltada = self._saltadas.pop((h.dh, h.n), None)
        if clave_saltada is not None:
            return _descifrar(clave_saltada, mensaje.cifrado, ad).decode("utf-8")

        if h.dh != self._dhr:
            if h.dh in self._dh_antiguas:
                raise MensajeRechazado("repetición: mensaje de una cadena ya cerrada")
            self._saltar(h.pn)
            self._paso_dh_recepcion(h.dh)
        elif h.n < self._nr:
            raise MensajeRechazado("repetición: la clave de ese mensaje ya se usó")

        self._saltar(h.n)
        self._ckr, clave_mensaje = kdf_ck(self._ckr)
        self._nr += 1
        return _descifrar(clave_mensaje, mensaje.cifrado, ad).decode("utf-8")

    def _paso_dh_recepcion(self, publica_nueva: bytes) -> None:
        self._pn = self._ns
        self._ns = 0
        self._nr = 0
        if self._dhr is not None:
            self._dh_antiguas.add(self._dhr)
        self._dhr = publica_nueva
        self._raiz, self._ckr = kdf_rk(self._raiz, _dh(self._dhs, self._dhr))
        self._cks = None  # la próxima vez que se envíe habrá cambio de dirección
        self._cambio_pendiente = True

    def _saltar(self, hasta: int) -> None:
        if self._ckr is None:
            return
        if hasta - self._nr > MAX_SALTO:
            raise MensajeRechazado("demasiados mensajes saltados")
        while self._nr < hasta:
            self._ckr, clave = kdf_ck(self._ckr)
            self._saltadas[(self._dhr, self._nr)] = clave
            self._nr += 1

    def _copiar_estado(self) -> dict:
        estado = dict(vars(self))
        estado["_saltadas"] = dict(self._saltadas)
        estado["_dh_antiguas"] = set(self._dh_antiguas)
        return estado

    def _restaurar_estado(self, estado: dict) -> None:
        vars(self).clear()
        vars(self).update(estado)

    # ------------------------------------------------------- para pruebas

    def exportar_estado(self) -> dict:
        """Copia de todo el estado secreto, como lo vería un atacante que lo roba."""
        return {
            "raiz": self._raiz,
            "cks": self._cks,
            "ckr": self._ckr,
            "dhs_privada": self._dhs.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            ),
            "dhr": self._dhr,
            "saltadas": dict(self._saltadas),
        }


def crear_sesion() -> tuple[Ratchet, Ratchet]:
    """Crea una sesión local entre Alicia (inicia) y Beto (responde).

    El secreto inicial se genera con ``os.urandom`` y simula el resultado de
    un acuerdo X3DH. No se usan datos reales de ninguna persona.
    """
    secreto = os.urandom(32)
    par_beto = X25519PrivateKey.generate()
    ad = b"alicia|beto"
    beto = Ratchet("beto", secreto, par_propio=par_beto, datos_asociados=ad)
    alicia = Ratchet(
        "alicia", secreto, publica_remota=_publica_bytes(par_beto), datos_asociados=ad
    )
    return alicia, beto


def atacante_intenta_descifrar(
    estado: dict, mensaje: Mensaje, datos_asociados: bytes = b"alicia|beto",
    pasos: int = 20,
) -> bool:
    """Simula a un atacante con un estado robado que intenta leer ``mensaje``.

    Prueba todas las claves que puede calcular con lo robado: claves saltadas,
    las cadenas de envío y recepción (avanzando hasta ``pasos`` mensajes) y
    las cadenas que salen de combinar la clave raíz con cada DH posible entre
    la clave privada robada y las públicas conocidas (dos pasos de raíz).

    Returns:
        ``True`` si logra descifrar el mensaje; ``False`` si no.
    """
    ad = datos_asociados + mensaje.encabezado.a_bytes()
    claves = list(estado["saltadas"].values())
    cadenas = [c for c in (estado["cks"], estado["ckr"]) if c is not None]

    privada = X25519PrivateKey.from_private_bytes(estado["dhs_privada"])
    publicas = {p for p in (mensaje.encabezado.dh, estado["dhr"]) if p is not None}
    for publica in publicas:
        salida = _dh(privada, publica)
        raiz1, cadena1 = kdf_rk(estado["raiz"], salida)
        _, cadena2 = kdf_rk(raiz1, salida)
        cadenas += [cadena1, cadena2]

    for cadena in cadenas:
        for _ in range(pasos):
            cadena, clave = kdf_ck(cadena)
            claves.append(clave)

    for clave in claves:
        try:
            _descifrar(clave, mensaje.cifrado, ad)
            return True
        except InvalidTag:
            continue
    return False
