// Edge Function: despachar-otp
// El cliente solo manda { usuario_id, canal }. NUNCA un destino: el correo o
// teléfono se busca aquí, con la llave de servicio, en contactos_recuperacion
// (la que registró la persona antes, desde Ajustes o "Mi acceso"). Así nadie
// puede escribir un correo propio en la pantalla de login y robarse un código
// ajeno.
//
// Requiere, configurados como secrets de este proyecto (Project Settings →
// Edge Functions → Secrets):
//   RESEND_API_KEY                 (obligatorio para canal 'email')
//   TWILIO_ACCOUNT_SID             (solo si se usará el canal 'sms')
//   TWILIO_AUTH_TOKEN              (solo si se usará el canal 'sms')
//   TWILIO_PHONE_NUMBER            (solo si se usará el canal 'sms')
// SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY ya los inyecta Supabase solo.
//
// Mientras RESEND_API_KEY no esté configurado, todo intento por 'email'
// devuelve un error claro (no falla en silencio).

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const escaparHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const { usuario_id, canal, nombre } = await req.json();

    if (!usuario_id || (canal !== "email" && canal !== "sms")) {
      return new Response(JSON.stringify({ ok: false, error: "Datos inválidos." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabaseAdmin = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    );

    // 1) El código activo (lo generó rpc_generar_codigo_recuperacion antes de esta llamada)
    const { data: registro, error: dbError } = await supabaseAdmin
      .from("recuperacion_codigos")
      .select("codigo")
      .eq("usuario_id", usuario_id)
      .eq("canal", canal)
      .eq("utilizado", false)
      .gt("expira_en", new Date().toISOString())
      .order("creado_en", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (dbError || !registro) {
      return new Response(JSON.stringify({ ok: false, error: "No hay una solicitud activa para esta persona." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const pin = registro.codigo as string;

    // 2) El destino real, SIEMPRE desde la tabla, nunca desde lo que mande el cliente
    const { data: contacto, error: contactoError } = await supabaseAdmin
      .from("contactos_recuperacion")
      .select("email, telefono")
      .eq("usuario_id", usuario_id)
      .maybeSingle();

    const destino = canal === "email" ? contacto?.email : contacto?.telefono;
    if (contactoError || !destino) {
      return new Response(JSON.stringify({ ok: false, error: "No hay un contacto registrado para esta persona." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (canal === "email") {
      const resendKey = Deno.env.get("RESEND_API_KEY");
      if (!resendKey) {
        return new Response(JSON.stringify({ ok: false, error: "Falta configurar RESEND_API_KEY en este proyecto de Supabase." }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const resendRes = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${resendKey}`,
        },
        body: JSON.stringify({
          from: Deno.env.get("RESEND_FROM") || "POS <onboarding@resend.dev>",
          to: [destino],
          subject: `Código de recuperación: ${pin}`,
          html: `<div style="font-family: sans-serif; padding: 20px; background: #F5F3ED; color: #191B1F;">
                   <h2 style="color: #D97E26;">POS</h2>
                   <p>Hola ${nombre ? escaparHtml(String(nombre).slice(0, 60)) : ""},</p>
                   <p>Tu código de recuperación es:</p>
                   <div style="font-size: 26px; font-weight: 800; letter-spacing: 5px; padding: 12px; background: #FFF; border: 1px solid #E0DBD0; text-align: center; border-radius: 8px;">
                     ${pin}
                   </div>
                   <p style="font-size: 11px; color: #63666A; margin-top: 15px;">Vence en 10 minutos. Si tú no pediste esto, ignora este correo.</p>
                 </div>`,
        }),
      });
      if (!resendRes.ok) {
        const detalle = await resendRes.text().catch(() => "");
        return new Response(JSON.stringify({ ok: false, error: "Resend no pudo enviar el correo.", detalle }), {
          status: 502,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    } else {
      const sid = Deno.env.get("TWILIO_ACCOUNT_SID");
      const token = Deno.env.get("TWILIO_AUTH_TOKEN");
      const from = Deno.env.get("TWILIO_PHONE_NUMBER");
      if (!sid || !token || !from) {
        return new Response(JSON.stringify({ ok: false, error: "Falta configurar Twilio (TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_PHONE_NUMBER) en este proyecto de Supabase." }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const bodyParams = new URLSearchParams({
        To: destino,
        From: from,
        Body: `POS: tu código de seguridad es ${pin}. Vence en 10 minutos.`,
      });
      const smsRes = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
        method: "POST",
        headers: {
          Authorization: "Basic " + btoa(`${sid}:${token}`),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: bodyParams.toString(),
      });
      if (!smsRes.ok) {
        const detalle = await smsRes.text().catch(() => "");
        return new Response(JSON.stringify({ ok: false, error: "Twilio no pudo enviar el SMS.", detalle }), {
          status: 502,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    return new Response(JSON.stringify({ ok: true }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: err instanceof Error ? err.message : String(err) }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
