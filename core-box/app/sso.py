"""Módulo SSO do Core Box (LABORATÓRIO Dia 03) — login federado via OIDC.

O Banco Box passou a aceitar login por um Provedor de Identidade (IdP) corporativo
usando OpenID Connect. Este módulo recebe o id_token e deveria validá-lo.

Contém fraquezas INTENCIONAIS de OAuth 2.0 / OIDC e de manuseio de JWT para o
aluno analisar (ver catálogo SSO-xx no Caderno do Aluno). Há também um
"inspetor de token" — ferramenta legítima que o aluno usa na análise.
"""
import base64
import hashlib
import hmac
import json
import time

import jwt
from flask import Blueprint, render_template, request, make_response, redirect

from app import auditoria
from app.db import get_db
from app.seguranca import emitir_token  # reaproveita a sessão do Core Box

bp = Blueprint("sso", __name__, url_prefix="/sso")

# SSO-11: segredo HMAC fraquíssimo e no código (permite forjar/crackear o token)
IDP_HMAC_SECRET = "secret"
# O IdP de homologação "deveria" ser validado, mas nada disso é conferido:
EMISSOR_ESPERADO = "https://idp.bancobox.example/realms/box"   # nunca comparado (SSO-06)
AUDIENCIA_ESPERADA = "core-box-web"                            # nunca comparada (SSO-05)


def _b64url(dados):
    return base64.urlsafe_b64encode(json.dumps(dados, separators=(",", ":")).encode()).rstrip(b"=").decode()


def gerar_id_token(usuario, conta, alg="HS256"):
    """IdP SIMULADO: emite um id_token OIDC com os defeitos INTENCIONAIS do laboratório.

    Mantém: sem nonce/jti/azp/at_hash (SSO-03/08/12), exp de 30 dias (SSO-07),
    dados sensíveis no payload (SSO-09), escopo excessivo (SSO-13), email_verified=false
    (SSO-15), identificação por username mutável (SSO-16). Assinado com HS256 e segredo
    fraco (SSO-11) ou, se alg='none', SEM assinatura (SSO-01).
    """
    agora = int(time.time())
    payload = {
        "iss": EMISSOR_ESPERADO, "sub": (usuario["nome"].split()[0] + "." + usuario["cpf"][:3]).lower(),
        "preferred_username": usuario["cpf"], "cpf": usuario["cpf"], "name": usuario["nome"],
        "email": (usuario["nome"].split()[0].lower() + "@exemplo.com"), "email_verified": False,
        "conta": conta["numero"] if conta else None, "agencia": conta["agencia"] if conta else None,
        "saldo": conta["saldo"] if conta else None, "limite_pix": conta["limite_diurno"] if conta else None,
        "senha_hash": usuario["senha_hash"],                 # SSO-09: hash de senha no token!
        "telefone": usuario["celular"], "role": usuario["perfil"],
        "scope": "openid profile accounts:write admin:all",  # SSO-13
        "db_host": "10.0.2.9", "reset_link": "http://core-box/reset?t=abc123",  # SSO-09
        "iat": agora, "exp": agora + 60 * 60 * 24 * 30,      # SSO-07: 30 dias; sem nonce/jti/azp/at_hash
    }
    header = {"alg": alg, "typ": "JWT"}
    h, p = _b64url(header), _b64url(payload)
    if alg == "none":
        return f"{h}.{p}."                                   # SSO-01: sem assinatura
    sig = hmac.new(IDP_HMAC_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


def _decodificar_sem_verificar(token):
    """Decodifica header+payload só para exibição no inspetor (uso legítimo)."""
    def b64(seg):
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "ignore"))
    try:
        h, p, _ = token.split(".")
        return b64(h), b64(p)
    except Exception:
        return {}, {}


@bp.route("/login")
def login():
    # SSO-04: a requisição de autorização NÃO usa PKCE (sem code_challenge) e
    # SSO-03: NÃO envia nonce. Fluxo implícito (SSO-17), escopo excessivo (SSO-13).
    # Agora aponta para o IdP SIMULADO local (/sso/idp/authorize), então o fluxo funciona.
    authorize_url = ("/sso/idp/authorize"
                     "?response_type=token%20id_token"
                     "&client_id=" + AUDIENCIA_ESPERADA +
                     "&redirect_uri=/sso/callback"
                     "&scope=openid%20profile%20accounts:write%20admin:all")
    return render_template("sso_login.html", authorize_url=authorize_url)


@bp.route("/idp/authorize")
def idp_authorize():
    """IdP SIMULADO — tela de autorização (equivale ao login no provedor de identidade).

    Em um IdP real, aqui o usuário se autenticaria. No laboratório, escolhe-se o usuário
    a simular. Repare que a requisição que chegou NÃO traz nonce nem PKCE (SSO-03/04).
    """
    usuarios = get_db().execute(
        "SELECT u.cpf, u.nome, u.perfil FROM usuarios u ORDER BY u.perfil DESC, u.nome").fetchall()
    return render_template("sso_idp.html", usuarios=usuarios,
                           redirect_uri=request.args.get("redirect_uri", "/sso/callback"))


@bp.route("/idp/emitir")
def idp_emitir():
    """IdP SIMULADO — emite o id_token e redireciona de volta ao callback (fluxo implícito)."""
    db = get_db()
    cpf = request.args.get("cpf", "")
    alg = request.args.get("alg", "HS256")   # 'none' permite demonstrar SSO-01
    usuario = db.execute("SELECT * FROM usuarios WHERE cpf = ?", (cpf,)).fetchone()
    if usuario is None:
        return make_response({"erro": "usuário não encontrado no IdP"}, 404)
    conta = db.execute("SELECT * FROM contas WHERE usuario_id = ?", (usuario["id"],)).fetchone()
    token = gerar_id_token(usuario, conta, alg=alg)
    # SSO-10: o token volta na URL (query string) para o redirect_uri
    destino = request.args.get("redirect_uri", "/sso/callback")
    return redirect(destino + ("&" if "?" in destino else "?") + "id_token=" + token)


@bp.route("/callback")
def callback():
    # SSO-10: token trafega na URL (vai parar em logs, histórico, Referer)
    token = request.args.get("id_token", "")
    if not token:
        return redirect("/sso/login")

    header, _ = _decodificar_sem_verificar(token)
    alg = (header.get("alg") or "").lower()

    try:
        if alg == "none":
            # SSO-01: aceita token SEM assinatura (alg: none)
            _, claims = _decodificar_sem_verificar(token)
        else:
            # SSO-02: decodifica SEM verificar assinatura, emissor, audiência, exp...
            claims = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        return make_response({"erro": "token inválido", "detalhe": str(e)}, 400)

    # Faz login com base no que veio no token, confiando cegamente (SSO-05/06/07/09)
    cpf = claims.get("cpf") or claims.get("preferred_username", "")
    db = get_db()
    usuario = db.execute("SELECT * FROM usuarios WHERE cpf = ?", (cpf,)).fetchone()
    if usuario is None:
        return make_response({"erro": "cliente não encontrado para o token"}, 404)

    auditoria.registrar(usuario["id"], "SSO_LOGIN", {"iss": claims.get("iss"), "alg": alg})
    resp = make_response(redirect("/home"))
    resp.set_cookie("box_token", emitir_token(usuario))
    return resp


@bp.route("/inspecionar", methods=["GET", "POST"])
def inspecionar():
    """Inspetor de token — ferramenta de análise do laboratório."""
    header = payload = None
    token = ""
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        header, payload = _decodificar_sem_verificar(token)
    hj = json.dumps(header, indent=2, ensure_ascii=False) if header else None
    pj = json.dumps(payload, indent=2, ensure_ascii=False) if payload else None
    return render_template("sso_inspecionar.html", token=token, header=header, payload=payload,
                           header_json=hj, payload_json=pj)
