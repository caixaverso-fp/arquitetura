"""Observabilidade do Core Box (Dia 04).

Ativa logs ESTRUTURADOS em arquivo para serem lidos por um agente Wazuh:
 - /var/log/box/access.log    uma linha por requisição HTTP (volumetria, status, latência)
 - /var/log/box/app.log       eventos de aplicação e de segurança (AUDITORIA / SECURITY_EVENT)

Formato pensado para decodificação por regex (key="value"), estável e fácil de parsear.
Ativação (no wsgi.py):   from app import observabilidade; observabilidade.ativar(app)
O diretório de logs pode ser trocado com a variável de ambiente BOX_LOG_DIR.
"""
import logging
import os
import time
from logging.handlers import RotatingFileHandler

from flask import g, request

LOG_DIR = os.getenv("BOX_LOG_DIR", "/var/log/box")


def _handler(nome, fmt):
    h = RotatingFileHandler(os.path.join(LOG_DIR, nome), maxBytes=20 * 1024 * 1024, backupCount=5)
    h.setFormatter(logging.Formatter(fmt))
    return h


def ativar(app):
    os.makedirs(LOG_DIR, exist_ok=True)

    # --- Log de aplicação/segurança: captura o que os módulos já emitem ---
    # (AUDITORIA acao=... / SECURITY_EVENT tipo=...), com data ISO e nível.
    app_log = _handler("app.log", '%(asctime)s host=corebox logger=%(name)s nivel=%(levelname)s %(message)s')
    box_logger = logging.getLogger("box")
    box_logger.setLevel(logging.INFO)
    box_logger.addHandler(app_log)
    box_logger.propagate = True

    # --- Log de acesso HTTP: uma linha por requisição ---
    acc = logging.getLogger("box.access")
    acc.setLevel(logging.INFO)
    acc.addHandler(_handler("access.log", '%(asctime)s %(message)s'))
    acc.propagate = False

    @app.before_request
    def _inicio():
        g._t0 = time.monotonic()

    @app.after_request
    def _acesso(resp):
        try:
            dur = int((time.monotonic() - getattr(g, "_t0", time.monotonic())) * 1000)
            ip = request.headers.get("X-Forwarded-For", request.remote_addr or "-").split(",")[0].strip()
            usuario = getattr(getattr(g, "usuario", None), "__getitem__", lambda k: "-")("id") if getattr(g, "usuario", None) else "-"
            ua = (request.headers.get("User-Agent", "-") or "-").replace('"', "'")[:160]
            acc.info('host=corebox ip=%s metodo=%s path="%s" status=%s dur_ms=%s user=%s ua="%s"',
                     ip, request.method, request.full_path.rstrip("?"), resp.status_code, dur, usuario, ua)
        except Exception:
            pass
        return resp

    app.logger.info("Observabilidade do Core Box ativada em %s", LOG_DIR)
    return app
