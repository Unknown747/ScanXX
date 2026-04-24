import { CONFIG } from "./config.js";
import { c, C } from "./ui.js";

export async function notifyTelegram(text) {
  const t = CONFIG.telegram;
  if (!t || !t.enabled || !t.botToken || !t.chatId) return;
  try {
    const url = "https://api.telegram.org/bot" + t.botToken + "/sendMessage";
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chat_id: t.chatId,
        text,
        parse_mode: "Markdown",
        disable_web_page_preview: true,
      }),
    });
    if (!r.ok) {
      console.log(c(C.yellow, "Telegram gagal: HTTP " + r.status));
    } else {
      console.log(c(C.dim, "Telegram terkirim ke chat " + t.chatId));
    }
  } catch (e) {
    console.log(c(C.yellow, "Telegram error: " + e.message));
  }
}
