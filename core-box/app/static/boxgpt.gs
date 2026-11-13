(function () {
  const chat = document.getElementById("chat");
  const input = document.getElementById("msg");
  const botao = document.getElementById("enviar");

  function bolha(txt, cls) {
    const d = document.createElement("div");
    d.className = "bolha " + cls;
    d.innerHTML = txt; // AI-10 (laboratório): saída do agente como HTML
    chat.appendChild(d);
    chat.scrollTop = chat.scrollHeight;
  }

  async function enviar() {
    const t = (input.value || "").trim();
    if (!t) return;
    bolha(t, "cli");
    input.value = "";
    try {
      const r = await fetch("/assistente/api/mensagem", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ texto: t }),
      });
      const j = await r.json();
      bolha(j.resposta, "bot");
    } catch (e) {
      bolha("[erro de comunicação com o BoxGPT]", "bot");
    }
  }

  botao.addEventListener("click", enviar);
  input.addEventListener("keydown", function (ev) { if (ev.key === "Enter") enviar(); });
})();
