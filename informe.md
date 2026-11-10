# Informe: seguridad en mensajería (E2EE y forward secrecy)

**Autor:** Tomás Marín Ariza

## Qué se implementó

**A1: cadena de claves simétrica (`a1_cadena.py`).**
`derivar_clave(cadena, indice)` obtiene la clave de cada mensaje con HKDF-SHA256,
incluyendo el índice en el parámetro `info`. `avanzar_cadena` mueve la cadena
en un solo sentido. `cifrar(clave, texto)` usa AES-256-GCM con un nonce
aleatorio. La clase `CadenaSimetrica` entrega una clave por mensaje y la borra
en cuanto se usa. Si se vuelve a pedir, lanza `ClaveNoDisponible`.

**A2: Double Ratchet reducido (`a2_ratchet.py`).**
La clase `Ratchet` tiene los métodos `enviar`, `recibir` y `cambiar_direccion`.
- Ratchet DH con X25519: `cambiar_direccion` genera un par nuevo y mezcla el
  secreto DH en la clave raíz (`kdf_rk`, HKDF-SHA256).
- Ratchet simétrico con HMAC-SHA256 (`kdf_ck`), como recomienda la
  especificación de Signal.
- Cifrado AES-256-GCM. El encabezado (clave pública, PN, N) va autenticado como
  dato asociado.
- Rechazo de mensajes alterados, rechazo de repeticiones y manejo de mensajes
  desordenados con claves saltadas (máximo 100).
- Si un mensaje se rechaza, el estado se restaura sin cambios.

Todo corre en un solo proceso y en memoria, sin red. El guion de prueba tiene 6
mensajes: Alicia envía m1–m3; Beto cambia de dirección (par X25519 nuevo) y
envía m4–m6.

**Pruebas.** `test_a1.py` y `test_a2.py` tienen una función por fila de la
tabla (`test_A1_01_...` corresponde a `A1-01`). `conftest.py` toma el valor
esperado de `resultados.csv`, llena las columnas `obtenido`, `estado` y
`comentario` y escribe `log_pruebas.json`. Para A2-04 y A2-05 se simula un
atacante (`atacante_intenta_descifrar`) que, con el estado robado, prueba todas
las claves que puede calcular. Cada una de esas pruebas incluye un **control
positivo**: un caso en que el atacante sí debe poder descifrar. Así se
comprueba que el "no descifrable" se debe a la protección y no a un ataque mal
programado.

**Resultado: 9 de 9 pruebas en OK (100 %).**

## Diferencias

**Frente a los valores esperados:** no hubo diferencias. Las 9 filas obtuvieron
exactamente el valor esperado y no hay ninguna FALLA que justificar.

**Hallazgo en A2-05:** el control mostró que, si se roba el estado de **Alicia**
en el mismo instante, ella sí puede leer m4. Esto no contradice la prueba, que
roba el estado de Beto. Ilustra que la seguridad poscompromiso solo se recupera
cuando **el participante comprometido** genera un par DH nuevo, que es el
comportamiento descrito por Signal.

**Frente al protocolo Signal real:**

| Aspecto | Signal | Esta versión |
|---|---|---|
| Secreto inicial | X3DH / PQXDH con claves de identidad | `os.urandom(32)` simulado |
| Cifrado del mensaje | AES-256-CBC + HMAC-SHA256 | AES-256-GCM |
| Encabezados | Opcionalmente cifrados | En claro, pero autenticados |
| Cambio de dirección | Automático al recibir | Explícito con `cambiar_direccion` (o automático al `enviar`) |
| Capa poscuántica | SPQR / Triple Ratchet (2025) | No incluida |
| Transporte | Servidor y red | Un solo proceso en memoria |

## Limitaciones

- **Borrado de claves:** Python no garantiza borrar la memoria. `del` y el
  descarte de referencias eliminan el acceso lógico, pero el recolector de
  basura puede dejar copias en RAM hasta que se reutilice esa zona.
- **Sin autenticación de identidad:** no hay claves de identidad ni verificación
  de números de seguridad, así que no se protege contra un intermediario en el
  acuerdo inicial.
- **Atacante acotado:** el atacante simulado prueba las derivaciones razonables
  (20 pasos por cadena, dos pasos de raíz). Es una evidencia experimental, no
  una demostración formal. La garantía formal está en Cohn-Gordon et al.
- **Metadatos:** los encabezados viajan en claro (clave pública y contadores).
- **Escala reducida:** solo hay dos participantes, 6 mensajes y un cambio de
  dirección. No hay grupos, varios dispositivos ni persistencia en disco.
- **Ética y datos:** todo es código propio y se ejecuta en local. No se usaron
  apps reales, cuentas ni datos personales (Ley 1581 de 2012).
