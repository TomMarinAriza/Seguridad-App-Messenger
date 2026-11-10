# Ficha: cifrado extremo a extremo y forward secrecy

**Autor:** Tomás Marín Ariza

## Definición

**¿Qué protege el cifrado extremo a extremo (E2EE) y qué no protege?**
En E2EE solo los dispositivos de emisor y receptor tienen las claves. El servidor
transporta mensajes que no puede leer ni modificar sin que se note.

- **Protege:** la confidencialidad del contenido (texto, archivos, audio) y su
  integridad y autenticidad frente al proveedor del servicio, la red y
  cualquiera que intercepte el tráfico.
- **No protege:** los metadatos (quién habla con quién, cuándo, con qué
  frecuencia, dirección IP, tamaño de los mensajes); un dispositivo comprometido
  (malware, teléfono desbloqueado); las copias de seguridad sin cifrar; lo que el
  receptor haga con el mensaje (capturas, reenvíos); ni la suplantación de un
  contacto si nunca se verifican las claves (número de seguridad).

## Amenaza

**¿Qué es el secreto hacia adelante (forward secrecy) y qué amenaza mitiga?**
Hay forward secrecy cuando robar las claves de hoy no permite descifrar los
mensajes de ayer. Mitiga la amenaza de **"guardar ahora, descifrar después"**:
un adversario graba el tráfico cifrado durante meses y luego roba el teléfono o
su estado de claves. Sin forward secrecy, todo lo grabado quedaría expuesto; con
ella, las claves de los mensajes pasados ya no existen y no se pueden derivar de
las actuales.

Su complemento es la **seguridad poscompromiso** (*post-compromise security*):
si el atacante roba el estado, la sesión "se cura" cuando la víctima vuelve a
generar claves frescas, y el atacante pierde el acceso a los mensajes futuros.

## Mecanismo

**¿Cómo logra Signal esa propiedad con su cadena de claves?**

1. **Acuerdo inicial (X3DH, hoy PQXDH):** las partes derivan un secreto
   compartido que se usa como primera clave raíz.
2. **Ratchet simétrico (cadena de claves):** cada cadena aplica una función de
   derivación de un solo sentido (HMAC-SHA256) para obtener una clave por
   mensaje y la siguiente clave de cadena. Cada clave de mensaje se borra en
   cuanto se usa. Como la función no se puede invertir, el estado actual no
   revela las claves anteriores: esto es el **forward secrecy**.
3. **Ratchet de Diffie-Hellman:** cada vez que cambia la dirección de la
   conversación, quien responde genera un par X25519 nuevo y mezcla el secreto
   DH en la clave raíz con HKDF. Eso abre cadenas nuevas que un atacante con el
   estado viejo no puede calcular: esto da la **seguridad poscompromiso**.

La combinación de ambos ratchets es el *Double Ratchet*. Cohn-Gordon et al.
demostraron formalmente que el protocolo cumple estas propiedades. Desde
octubre de 2025 Signal añade además un ratchet poscuántico (SPQR, con ML-KEM)
que funciona en paralelo al anterior (*Triple Ratchet*).

## Fuentes

1. Cohn-Gordon, K., Cremers, C., Dowling, B., Garratt, L. y Stebila, D. (2017).
   *A Formal Security Analysis of the Signal Messaging Protocol*. IEEE European
   Symposium on Security and Privacy (EuroS&P 2017). https://eprint.iacr.org/2016/1013
2. Perrin, T. y Marlinspike, M. (2016). *The Double Ratchet Algorithm*
   (especificación del protocolo Signal, rev. 1).
   https://signal.org/docs/specifications/doubleratchet/
3. Marlinspike, M. y Perrin, T. (2016). *The X3DH Key Agreement Protocol*.
   https://signal.org/docs/specifications/x3dh/
4. Signal (2025). *Signal Protocol and Post-Quantum Ratchets*.
   https://signal.org/blog/spqr/
