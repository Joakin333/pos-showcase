// Edge Function: notificar-venta
// La llama el trigger fn_notificar_venta_nueva (via pg_net) cada vez que se inserta
// una fila en ventas_registro que no es un abono. Manda un Web Push a cada
// dispositivo suscrito. No la llama el navegador directamente: se valida con un
// secreto compartido (x-webhook-secret), no con el JWT de Supabase (por eso
// verify_jwt=false en supabase/config.toml).
//
// Deploy: supabase functions deploy notificar-venta
// Secrets (una sola vez, no se versionan acá): supabase secrets set VAPID_PUBLIC_KEY=... VAPID_PRIVATE_KEY=... WEBHOOK_SECRET=...

import webpush from "npm:web-push@3.6.7";
import { createClient } from "npm:@supabase/supabase-js@2";

const VAPID_PUBLIC_KEY = Deno.env.get("VAPID_PUBLIC_KEY") ?? "";
const VAPID_PRIVATE_KEY = Deno.env.get("VAPID_PRIVATE_KEY") ?? "";
const WEBHOOK_SECRET = Deno.env.get("WEBHOOK_SECRET") ?? "";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
// Nombre del negocio y contacto del aviso: secrets NOMBRE_NEGOCIO y CONTACTO_VAPID (opcionales).
const NEGOCIO = Deno.env.get("NOMBRE_NEGOCIO") ?? "POS";
const CONTACTO_VAPID = Deno.env.get("CONTACTO_VAPID") ?? "mailto:soporte@example.com";

if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(CONTACTO_VAPID, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
}

Deno.serve(async (req) => {
  if (!WEBHOOK_SECRET || req.headers.get("x-webhook-secret") !== WEBHOOK_SECRET) {
    return new Response("no autorizado", { status: 401 });
  }
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    return new Response("faltan las llaves VAPID (secrets sin configurar)", { status: 500 });
  }

  let body: any = null;
  try { body = await req.json(); } catch (_e) { /* sin body valido */ }
  const venta = body?.data ?? null;
  if (!venta) return new Response("sin datos de venta", { status: 400 });

  const metodo = Array.isArray(venta.pagos) && venta.pagos.length
    ? venta.pagos.map((p: any) => p.metodo).join(" + ")
    : (venta.metodoResumen || "");
  const total = Number(venta.total || 0).toLocaleString("es-CL");
  const operador = venta.operador || "Alguien";
  const titulo = `${NEGOCIO} \u2014 Nueva venta`;
  const cuerpo = `${operador} registr\u00f3 una venta por $${total}${metodo ? ` (${metodo})` : ""}`;

  const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);
  const { data: subs, error } = await supabase.from("push_suscripciones").select("id, endpoint, p256dh, auth");
  if (error) return new Response("error leyendo suscripciones: " + error.message, { status: 500 });

  const payload = JSON.stringify({ title: titulo, body: cuerpo });

  await Promise.all((subs || []).map(async (s: any) => {
    try {
      await webpush.sendNotification(
        { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
        payload
      );
    } catch (e: any) {
      // 404/410 = el navegador dio de baja esa suscripción (desinstaló, borró datos, etc.)
      if (e?.statusCode === 404 || e?.statusCode === 410) {
        await supabase.from("push_suscripciones").delete().eq("id", s.id);
      }
    }
  }));

  return new Response("ok", { status: 200 });
});
