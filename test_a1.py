"""Pruebas de A1 (cadena de claves simétrica). Una función por fila de resultados.csv."""

import os

from cryptography.exceptions import InvalidTag

from a1_cadena import (
    CadenaSimetrica,
    ClaveNoDisponible,
    avanzar_cadena,
    derivar_clave,
    descifrar,
)


def test_A1_01_determinismo(resultado):
    cadena = os.urandom(32)
    clave_1 = derivar_clave(cadena, 5)
    clave_2 = derivar_clave(cadena, 5)
    otra_cadena = derivar_clave(os.urandom(32), 5)

    resultado.obtenido = "misma clave" if clave_1 == clave_2 else "claves distintas"
    resultado.comentario = (
        "derivar_clave(cadena, 5) dos veces da los mismos 32 bytes; "
        f"con otra cadena la clave cambia: {otra_cadena != clave_1}"
    )
    assert resultado.obtenido == resultado.esperado
    assert otra_cadena != clave_1


def test_A1_02_unicidad(resultado):
    cadena = CadenaSimetrica(os.urandom(32))
    claves = [cadena.tomar_clave(i) for i in range(10)]
    distintas = len(set(claves))

    resultado.obtenido = f"{distintas} claves distintas"
    resultado.comentario = "10 claves de 32 bytes derivadas en orden con HKDF-SHA256"
    assert resultado.obtenido == resultado.esperado


def test_A1_03_cifrado(resultado):
    inicial = os.urandom(32)
    emisor, receptor = CadenaSimetrica(inicial), CadenaSimetrica(inicial)
    textos = [f"Mensaje de prueba número {i}" for i in range(10)]

    enviados = [emisor.cifrar_siguiente(t) for t in textos]
    correctos = sum(
        receptor.descifrar_mensaje(indice, datos) == texto
        for (indice, datos), texto in zip(enviados, textos)
    )

    resultado.obtenido = f"{correctos}/10 correctos"
    resultado.comentario = "AES-256-GCM con una clave de mensaje distinta por cada uno"
    assert resultado.obtenido == resultado.esperado


def test_A1_04_borrado(resultado):
    inicial = os.urandom(32)
    emisor, receptor = CadenaSimetrica(inicial), CadenaSimetrica(inicial)
    indice, datos = emisor.cifrar_siguiente("mensaje secreto")
    assert receptor.descifrar_mensaje(indice, datos) == "mensaje secreto"
    clave_original = derivar_clave(inicial, 0)

    # 1) La cadena ya no entrega esa clave.
    try:
        receptor.tomar_clave(indice)
        borrada = False
    except ClaveNoDisponible:
        borrada = True

    # 2) Un atacante con el estado actual (después del uso) prueba 50 claves
    #    hacia adelante y no consigue la clave usada ni descifrar el mensaje.
    candidatas = []
    cadena = receptor.estado
    for j in range(50):
        candidatas.append(derivar_clave(cadena, j))
        cadena = avanzar_cadena(cadena)
    descifra = False
    for clave in candidatas:
        try:
            descifrar(clave, datos)
            descifra = True
        except InvalidTag:
            pass
    recuperada = clave_original in candidatas or descifra

    resultado.obtenido = (
        "no recuperable" if borrada and not recuperada else "recuperable"
    )
    resultado.comentario = (
        "La cadena lanza ClaveNoDisponible al pedir la clave 0 otra vez; con el "
        "estado robado después del uso se probaron 50 claves y ninguna descifra"
    )
    assert resultado.obtenido == resultado.esperado
    # Control: la clave original sí descifraba (el ataque no falla por error).
    assert descifrar(clave_original, datos) == "mensaje secreto"
