// Edge Function: despachar-otp
// El cliente solo manda { usuario_id, canal }. NUNCA un destino: el correo o
// telefono se busca aqui, con la llave de servicio, en contactos_recuperacion
// (la que registro la persona antes, desde Ajustes o Mi acceso). Asi nadie
// puede escribir un correo propio en la pantalla de login y robarse un codigo
// ajeno.
//
// Secrets del proyecto (Project Settings, Edge Functions, Secrets):
//   RESEND_API_KEY      (obligatorio para canal email)
//   TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER (solo canal sms)
//   NOMBRE_NEGOCIO      (opcional: aparece en el correo y el SMS; por defecto POS)
// SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY los inyecta Supabase solo.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const NEGOCIO = Deno.env.get("NOMBRE_NEGOCIO") || "POS";
const MENOR = String.fromCharCode(60);
const MAYOR = String.fromCharCode(62);
const COMILLA = String.fromCharCode(34);
// el nombre llega del navegador: se escapa antes de ponerlo en el HTML del correo
const escaparHtml = (s: string) =>
  s.split("&").join("&amp;").split(MENOR).join("&lt;").split(MAYOR).join("&gt;").split(COMILLA).join("&quot;");

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const json = (cuerpo: unknown, status = 200) =>
  new Response(JSON.stringify(cuerpo), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const { usuario_id, canal, nombre } = await req.json();
    if (!usuario_id || (canal !== "email" && canal !== "sms")) {
      return json({ ok: false, error: "Datos inválidos." }, 400);
    }

    const supabaseAdmin = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    );

    // 1) El codigo activo que todavia NO se envio (lo genero rpc_generar_codigo_recuperacion).
    //    Se reclama con un UPDATE condicionado: cada codigo se envia una sola vez, aunque
    //    esta funcion se llame muchas veces.
    const { data: candidato, error: dbError } = await supabaseAdmin
      .from("recuperacion_codigos")
      .select("id")
      .eq("usuario_id", usuario_id)
      .eq("canal", canal)
      .eq("utilizado", false)
      .eq("enviado", false)
      .gt("expira_en", new Date().toISOString())
      .order("creado_en", { ascending: false })
      .limit(1)
      .maybeSingle();
    const { data: registro } = candidato
      ? await supabaseAdmin.from("recuperacion_codigos").update({ enviado: true })
          .eq("id", candidato.id).eq("enviado", false).select("id, codigo").maybeSingle()
      : { data: null };
    if (dbError || !registro) {
      return json({ ok: false, error: "No hay una solicitud activa para esta persona." }, 400);
    }
    const pin = registro.codigo as string;
    // si el envio falla, se libera el codigo para poder reintentar
    const liberar = () => supabaseAdmin.from("recuperacion_codigos").update({ enviado: false }).eq("id", registro.id);

    // 2) El destino real, SIEMPRE desde la tabla, nunca desde lo que mande el cliente
    const { data: contacto, error: contactoError } = await supabaseAdmin
      .from("contactos_recuperacion")
      .select("email, telefono")
      .eq("usuario_id", usuario_id)
      .maybeSingle();
    const destino = canal === "email" ? contacto?.email : contacto?.telefono;
    if (contactoError || !destino) {
      await liberar();
      return json({ ok: false, error: "No hay un contacto registrado para esta persona." }, 400);
    }

    if (canal === "email") {
      const resendKey = Deno.env.get("RESEND_API_KEY");
      if (!resendKey) {
        await liberar();
        return json({ ok: false, error: "Falta configurar RESEND_API_KEY en este proyecto de Supabase." }, 500);
      }
      const abre = (etiqueta: string) => MENOR + etiqueta + MAYOR;
      const cierra = (etiqueta: string) => MENOR + "/" + etiqueta + MAYOR;
      const html =
        abre("div style=" + COMILLA + "font-family: sans-serif; padding: 20px; background: #F5F3ED; color: #191B1F;" + COMILLA) +
        abre("h2 style=" + COMILLA + "color: #D97E26;" + COMILLA) + escaparHtml(NEGOCIO) + cierra("h2") +
        abre("p") + "Hola " + (nombre ? escaparHtml(String(nombre).slice(0, 60)) : "") + "," + cierra("p") +
        abre("p") + "Tu código de recuperación es:" + cierra("p") +
        abre("div style=" + COMILLA + "font-size: 26px; font-weight: 800; letter-spacing: 5px; padding: 12px; background: #FFF; border: 1px solid #E0DBD0; text-align: center; border-radius: 8px;" + COMILLA) +
        pin + cierra("div") +
        abre("p style=" + COMILLA + "font-size: 11px; color: #63666A; margin-top: 15px;" + COMILLA) +
        "Vence en 10 minutos. Si tú no pediste esto, ignora este correo." + cierra("p") +
        cierra("div");
      const resendRes = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + resendKey },
        body: JSON.stringify({
          from: Deno.env.get("RESEND_FROM") || (NEGOCIO + " " + MENOR + "onboarding@resend.dev" + MAYOR),
          to: [destino],
          subject: "Código de recuperación: " + pin,
          html,
        }),
      });
      if (!resendRes.ok) {
        await liberar();
        const detalle = await resendRes.text().catch(() => "");
        return json({ ok: false, error: "Resend no pudo enviar el correo.", detalle }, 502);
      }
    } else {
      const sid = Deno.env.get("TWILIO_ACCOUNT_SID");
      const token = Deno.env.get("TWILIO_AUTH_TOKEN");
      const from = Deno.env.get("TWILIO_PHONE_NUMBER");
      if (!sid || !token || !from) {
        await liberar();
        return json({ ok: false, error: "Falta configurar Twilio (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER) en este proyecto de Supabase." }, 500);
      }
      const smsRes = await fetch("https://api.twilio.com/2010-04-01/Accounts/" + sid + "/Messages.json", {
        method: "POST",
        headers: { Authorization: "Basic " + btoa(sid + ":" + token), "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ To: destino, From: from, Body: NEGOCIO + ": tu código de seguridad es " + pin + ". Vence en 10 minutos." }).toString(),
      });
      if (!smsRes.ok) {
        await liberar();
        const detalle = await smsRes.text().catch(() => "");
        return json({ ok: false, error: "Twilio no pudo enviar el SMS.", detalle }, 502);
      }
    }

    return json({ ok: true });
  } catch (err) {
    return json({ ok: false, error: err instanceof Error ? err.message : String(err) }, 500);
  }
});
