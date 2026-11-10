"""Pruebas de A2 (Double Ratchet reducido). Una función por fila de resultados.csv.

Guion de los 6 mensajes: Alicia envía m1, m2 y m3 a Beto; hay un cambio de
dirección (Beto genera un par X25519 nuevo) y Beto envía m4, m5 y m6 a Alicia.
"""

from dataclasses import replace

from a2_ratchet import MensajeRechazado, atacante_intenta_descifrar, crear_sesion


def _rechaza(receptor, mensaje) -> bool:
    try:
        receptor.recibir(mensaje)
        return False
    except MensajeRechazado:
        return True


def test_A2_01_descifrado(resultado):
    alicia, beto = crear_sesion()
    textos = [f"m{i}: texto de prueba" for i in range(1, 7)]
    correctos = 0

    for texto in textos[:3]:
        correctos += beto.recibir(alicia.enviar(texto)) == texto

    publica_antes = beto.publica
    beto.cambiar_direccion()
    par_nuevo = beto.publica != publica_antes

    for texto in textos[3:]:
        correctos += alicia.recibir(beto.enviar(texto)) == texto

    resultado.obtenido = f"{correctos}/6 correctos"
    resultado.comentario = (
        "m1-m3 de Alicia a Beto; cambio de dirección con par X25519 nuevo de Beto "
        f"({par_nuevo}); m4-m6 de Beto a Alicia"
    )
    assert par_nuevo
    assert resultado.obtenido == resultado.esperado


def test_A2_02_integridad(resultado):
    alicia, beto = crear_sesion()
    m1 = alicia.enviar("mensaje íntegro")
    cifrado = bytearray(m1.cifrado)
    cifrado[0] ^= 0x01  # se altera un solo bit del primer byte
    alterado = replace(m1, cifrado=bytes(cifrado))

    resultado.obtenido = "rechazado" if _rechaza(beto, alterado) else "aceptado"
    intacto = beto.recibir(m1) == "mensaje íntegro"
    resultado.comentario = (
        "AES-GCM detecta la alteración (InvalidTag); el estado no cambia y el "
        f"mensaje original se descifra después: {intacto}"
    )
    assert intacto
    assert resultado.obtenido == resultado.esperado


def test_A2_03_repeticion(resultado):
    alicia, beto = crear_sesion()
    m1, m2 = alicia.enviar("uno"), alicia.enviar("dos")
    beto.recibir(m1)
    beto.recibir(m2)
    m3 = beto.enviar("tres")  # cambio de dirección automático
    alicia.recibir(m3)

    reenvios = [_rechaza(beto, m1), _rechaza(beto, m2), _rechaza(alicia, m3)]
    resultado.obtenido = "rechazado" if all(reenvios) else "aceptado"
    resultado.comentario = (
        f"{sum(reenvios)}/3 reenvíos rechazados (m1 y m2 a Beto, m3 a Alicia): "
        "la clave de cada mensaje se borra al usarla"
    )
    assert resultado.obtenido == resultado.esperado


def test_A2_04_forward_secrecy(resultado):
    alicia, beto = crear_sesion()
    m1, m2, m3 = (alicia.enviar(t) for t in ("m1", "m2", "m3"))
    beto.recibir(m1)
    beto.recibir(m2)
    estado_control = beto.exportar_estado()  # robado antes de recibir m3
    beto.recibir(m3)
    estado_robado = beto.exportar_estado()  # robado tras el mensaje 3

    lee_m1 = atacante_intenta_descifrar(estado_robado, m1)
    lee_m2 = atacante_intenta_descifrar(estado_robado, m2)
    control = atacante_intenta_descifrar(estado_control, m3)

    resultado.obtenido = "descifrable" if lee_m1 else "no descifrable"
    resultado.comentario = (
        "Con el estado de Beto tras m3 el atacante no lee m1 ni m2 "
        f"(m2 descifrado: {lee_m2}). Control: un estado robado antes de m3 sí "
        f"lee m3 ({control}), lo que confirma que el ataque simulado funciona"
    )
    assert control, "el atacante simulado debería poder leer m3 con el estado previo"
    assert not lee_m2
    assert resultado.obtenido == resultado.esperado


def test_A2_05_post_compromise(resultado):
    alicia, beto = crear_sesion()
    for t in ("m1", "m2", "m3"):
        beto.recibir(alicia.enviar(t))
    estado_robado = beto.exportar_estado()  # antes del cambio de dirección
    estado_otro_lado = alicia.exportar_estado()  # control (ver comentario)

    beto.cambiar_direccion()
    posteriores = [beto.enviar(t) for t in ("m4", "m5", "m6")]
    for m, t in zip(posteriores, ("m4", "m5", "m6")):
        assert alicia.recibir(m) == t

    leidos = sum(atacante_intenta_descifrar(estado_robado, m) for m in posteriores)
    control = atacante_intenta_descifrar(estado_otro_lado, posteriores[0])

    resultado.obtenido = "descifrable" if leidos else "no descifrable"
    resultado.comentario = (
        f"Con el estado de Beto robado antes del cambio se leen {leidos}/3 de "
        "m4-m6: el par X25519 nuevo sana la sesión. Control: el estado de Alicia "
        f"robado en ese momento sí lee m4 ({control}), porque Alicia aún no ha "
        "renovado su par; la recuperación ocurre cuando renueva el comprometido"
    )
    assert control
    assert resultado.obtenido == resultado.esperado
