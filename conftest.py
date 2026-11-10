"""Configuración de pytest: registra cada prueba en resultados.csv y log_pruebas.json.

Cada prueba se llama ``test_A1_01_...``, ``test_A2_05_...``, etc. Su nombre se
corresponde con el ``id_prueba`` de la fila de resultados.csv (A1-01, A2-05...).
La prueba recibe el fixture ``resultado``, toma de ahí el valor ``esperado``
de la tabla y anota lo ``obtenido``. Al terminar la sesión se llenan las
columnas obtenido, estado y comentario del CSV (sin tocar el encabezado) y se
escribe log_pruebas.json con una entrada por prueba.
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

import pytest

RAIZ = Path(__file__).parent
ARCHIVO_CSV = RAIZ / "resultados.csv"
ARCHIVO_LOG = RAIZ / "log_pruebas.json"

_registro: dict[str, dict] = {}


def _leer_csv() -> tuple[list[str], list[dict]]:
    with ARCHIVO_CSV.open(encoding="utf-8", newline="") as f:
        lector = csv.DictReader(f)
        return list(lector.fieldnames), list(lector)


def _id_prueba(nombre: str) -> str | None:
    m = re.match(r"test_(A\d)_(\d{2})", nombre)
    return f"{m.group(1)}-{m.group(2)}" if m else None


class Resultado:
    """Lo que una prueba anota sobre su fila de la tabla."""

    def __init__(self, id_prueba: str, esperado: str) -> None:
        self.id_prueba = id_prueba
        self.esperado = esperado
        self.obtenido: str | None = None
        self.comentario = ""


@pytest.fixture
def resultado(request) -> Resultado:
    id_prueba = _id_prueba(request.node.name)
    _, filas = _leer_csv()
    esperado = next(f["esperado"] for f in filas if f["id_prueba"] == id_prueba)
    r = Resultado(id_prueba, esperado)
    request.node._resultado = r
    return r


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    reporte = (yield).get_result()
    id_prueba = _id_prueba(item.name)
    if id_prueba is None or reporte.when != "call":
        return
    r = getattr(item, "_resultado", None)
    obtenido = r.obtenido if r and r.obtenido is not None else "error"
    comentario = r.comentario if r else ""
    if reporte.failed:
        estado = "FALLA"
        error = call.excinfo.exconly().splitlines()[0][:200] if call.excinfo else ""
        comentario = f"{comentario} Error: {error}".strip()
    else:
        estado = "OK"
    _registro[id_prueba] = {
        "obtenido": obtenido,
        "estado": estado,
        "comentario": comentario,
    }


def pytest_sessionfinish(session, exitstatus):
    if not _registro:
        return
    encabezado, filas = _leer_csv()
    for fila in filas:
        if fila["id_prueba"] in _registro:
            fila.update(_registro[fila["id_prueba"]])

    with ARCHIVO_CSV.open("w", encoding="utf-8", newline="") as f:
        escritor = csv.DictWriter(f, fieldnames=encabezado, lineterminator="\n")
        escritor.writeheader()
        escritor.writerows(filas)

    log = [
        {
            "prueba": fila["id_prueba"],
            "esperado": fila["esperado"],
            "obtenido": fila["obtenido"],
            "estado": fila["estado"],
        }
        for fila in filas
        if fila["estado"]
    ]
    ARCHIVO_LOG.write_text(
        json.dumps(log, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
