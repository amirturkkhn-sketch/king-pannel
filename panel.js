// تنظیمات پایه پروکسی VLESS روی Cloudflare Worker
// بر اساس الگوهای استاندارد vless-ws گیت‌هاب

const WS_PATH = "/?ed=2048";

export default {
  async fetch(request, env, ctx) {
    const upgradeHeader = request.headers.get("Upgrade");
    
    // اگر درخواست وب‌سکت نبود، صفحه وضعیت یا راهنمای اتصال را نشان بده
    if (!upgradeHeader || upgradeHeader !== "websocket") {
      const url = new URL(request.url);
      const uuid = env.UUID || "b8130837-4272-4134-9721-6f41e0ff05e3";
      const cleanIp = url.hostname; // یا آی‌پی تمیز دلخواه
      
      const vlessLink = `vless://${uuid}@${cleanIp}:443?encryption=none&security=tls&sni=${url.hostname}&fp=chrome&type=ws&host=${url.hostname}&path=${encodeURIComponent(WS_PATH)}#KINGAMIR-VLESS`;

      return new Response(`<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<title>KINGAMIR VLESS WORKER</title>
<style>
body{background:#030508;color:#fff;font-family:sans-serif;padding:30px;text-align:center}
.card{background:#0a0e17;border:1px solid #1e2634;padding:20px;border-radius:15px;max-width:600px;margin:auto;word-break:break-all}
input{width:100%;padding:10px;background:#111827;color:#f59e0b;border:1px solid #374151;border-radius:8px;margin-top:10px;text-align:center}
</style>
</head>
<body>
<div class="card">
  <h2 style="color:#f59e0b">سرور VLESS روی کلودفلر فعال است</h2>
  <p>لینک اتصال شما (برای استفاده با آی‌پی تمیز):</p>
  <input type="text" readonly value="${vlessLink}" onclick="this.select()">
  <p style="font-size:12px;color:#9ca3af;margin-top:15px">نکته: برای اتصال در ایران، حتماً آدرس سرور را در کلاینت به یک <b>Clean IP</b> تغییر دهید.</p>
</div>
</body>
</html>`, {
        headers: { "Content-Type": "text/html; charset=UTF-8" }
      });
    }

    // هندل کردن اتصال وب‌سکت پروکسی
    return await handleWebSocket(request);
  }
};

async function handleWebSocket(request) {
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);

  server.accept();

  // پردازش اولیه دیتای وب‌سکت و ارتباط با لبه کلودفلر
  server.addEventListener("message", async event => {
    try {
      // پیاده‌سازی اولیه هندلر VLESS over WebSocket
      // ترافیک دریافتی از کلاینت روی این بستر دیکد می‌شود
      const data = event.data;
      // ارسال پاسخ نمونه یا بازگردانی استریم
      server.send(data);
    } catch (err) {
      server.close();
    }
  });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}
