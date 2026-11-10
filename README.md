# Taller individual: Seguridad en Messenger

**Autor:** Tomás Marín Ariza

Implementación simplificada de una cadena de claves simétrica (A1) y de un
Double Ratchet reducido (A2), con pruebas automáticas que generan
`resultados.csv` y `log_pruebas.json`.

## Requisitos

- Python 3.11 o superior
- Bibliotecas: `cryptography` y `pytest` (ver `requirements.txt`)

## Instalar dependencias

```bash
python -m pip install -r requirements.txt
```

(Opcional) en un entorno virtual:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

## Ejecutar las pruebas

Desde esta carpeta:

```bash
python -m pytest -q
```

Salida esperada: `9 passed`. Al terminar, el comando:

- llena las columnas `obtenido`, `estado` y `comentario` de `resultados.csv`
  (el encabezado no se modifica);
- escribe `log_pruebas.json` con una entrada por prueba (`prueba`, `esperado`,
  `obtenido`, `estado`).

## Archivos

| Archivo | Contenido |
|---|---|
| `ficha.md` | Ficha del concepto: E2EE y forward secrecy |
| `a1_cadena.py` | A1: `derivar_clave(cadena, indice)`, `cifrar(clave, texto)` |
| `a2_ratchet.py` | A2: clase `Ratchet` con `enviar`, `recibir`, `cambiar_direccion` |
| `test_a1.py`, `test_a2.py` | Una prueba por fila (`test_A1_01_...` corresponde a `A1-01`) |
| `conftest.py` | Registra los resultados en el CSV y el JSON |
| `resultados.csv`, `log_pruebas.json` | Resultados generados por las pruebas |
| `informe.md` | Informe corto |

Todo se ejecuta en local, con datos simulados y sin red.
