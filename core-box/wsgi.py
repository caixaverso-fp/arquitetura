from app import create_app

app = create_app()

# Dia 04 — observabilidade (logs estruturados para o Wazuh)
try:
    from app import observabilidade
    observabilidade.ativar(app)
except Exception as _e:  # não derruba o app se o diretório de log não existir
    app.logger.warning('observabilidade não ativada: %s', _e)

if __name__ == "__main__":
    # Apenas desenvolvimento local; produção usa gunicorn (ver Dockerfile)
    app.run(host="0.0.0.0", port=8000)
