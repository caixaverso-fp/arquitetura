# Wazuh (SIEM) para o Core Box — Dia 04

O Wazuh é o "cérebro" de detecção: recebe os logs dos 8 grupos, aplica as regras do
Core Box e gera alertas correlacionados. O Grafana é o telão; o Wazuh é a central de alertas.

## 1. Subir o Wazuh central (VM do SOC)
Use o docker-compose single-node OFICIAL do Wazuh (manager + indexer + dashboard):

    git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
    cd wazuh-docker/single-node
    docker compose -f generate-indexer-certs.yml run --rm generator   # gera os certificados
    docker compose up -d

Acesse o Wazuh Dashboard em https://<IP_SOC>:443 (usuário/senha padrão no .env do repo —
TROQUE antes da aula).

## 2. Instalar as regras/decoders do Core Box
Copie para o container do manager (ou monte como volume) e reinicie:

    docker cp decoders/corebox_decoders.xml single-node-wazuh.manager-1:/var/ossec/etc/decoders/
    docker cp rules/corebox_rules.xml    single-node-wazuh.manager-1:/var/ossec/etc/rules/
    docker compose restart wazuh.manager

Teste os decoders/regras com uma linha real de log:

    docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
    # cole:  2026-11-13 10:16:31,296 host=corebox logger=box.auditoria nivel=WARNING SECURITY_EVENT tipo=BOLA_ATTEMPT ator=1 detalhe={}

## 3. Agente em cada VPS de grupo
Instale o wazuh-agent (pacote oficial), registre com nome do grupo e aponte para o manager:

    sudo WAZUH_MANAGER="<IP_SOC>" WAZUH_AGENT_NAME="corebox-grupo01" apt install wazuh-agent
    # adicione os <localfile> do arquivo agent-ossec.conf.snippet ao /var/ossec/etc/ossec.conf
    sudo systemctl enable --now wazuh-agent

## 4. Mapa de alertas (o que cada regra significa)
| Rule ID | Nível | Significado | MITRE |
|---|---|---|---|
| 100102 | 10 | Erro 5xx (indisponibilidade) | T1499 |
| 100131 | 12 | Credential stuffing / brute force | T1110.004 |
| 100140 | 12 | Volume anômalo (DoS/scan) | T1498 |
| 100111 | 12 | BOLA/IDOR (acesso a conta de terceiro) | T1190 |
| 100113 | 13 | Ajuste de saldo acima da alçada (fraude) | T1565 |
| 100114 | 11 | Exportação em massa (exfiltração) | T1567 |
| 100150 | 13 | SSO com token sem assinatura (alg:none) | T1212 |
