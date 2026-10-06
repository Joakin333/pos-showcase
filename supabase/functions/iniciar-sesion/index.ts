// Edge Function: iniciar-sesion
// Convierte "elijo mi nombre + escribo mi clave" en una sesión real de Supabase
// Auth, sin cambiar la experiencia en la caja.
//
//   POST { usuario_id, clave }                         → entrar
//   POST { usuario_id, restablecer: { metodo, prueba, bundle } }
//        metodo: 'respuesta' | 'maestro' | 'otp'       → recuperar acceso
//
// La clave (o la prueba de recuperación) se valida en Postgres con la llave de
// servicio: verificar_credencial (bloqueo de 5 intentos / 60 s) o
// fn_restablecer_clave (que además guarda la clave nueva en la misma operación).
// Si es correcta, se genera un enlace mágico SIN enviarlo por correo y se
// devuelve su token_hash; el navegador lo canjea con auth.verifyOtp() y queda
// con una sesión cuyo JWT lleva app_metadata.usuario_id. Ese campo solo lo puede
// escribir la llave de servicio, así que nadie puede hacerse pasar por otra
// persona editando su propio token.
//
// verify_jwt = false (supabase/config.toml): se llama ANTES de tener sesión.
// SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY los inyecta Supabase.

import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const responder = (cuerpo: unknown, status = 200) =>
  new Response(JSON.stringify(cuerpo), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

// IP real del llamador: la fija la infraestructura (Cloudflare). El primer valor
// de X-Forwarded-For lo puede escribir cualquiera, por eso se usa el último.
function ipDe(req: Request): string {
  const cf = req.headers.get("cf-connecting-ip") ?? req.headers.get("x-real-ip");
  if (cf) return cf.trim();
  const xff = (req.headers.get("x-forwarded-for") ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  return xff.length ? xff[xff.length - 1] : "sin-ip";
}
const MAX_INTENTOS_POR_IP = 40;   // por ventana
const VENTANA_IP_SEGUNDOS = 600;

// uid() del cliente: base36 → solo minúsculas y dígitos.
const ID_VALIDO = /^[a-z0-9]{4,40}$/;
const METODOS = new Set(["respuesta", "maestro", "otp"]);
// Dominio reservado (RFC 2606): nunca recibe correo, y generateLink no envía nada.
const correoInterno = (usuarioId: string) => `${usuarioId}@usuarios.pos.invalid`;

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return responder({ ok: false, mensaje: "Método no permitido." }, 405);

  let body: any;
  try {
    body = await req.json();
  } catch (_e) {
    return responder({ ok: false, mensaje: "Datos inválidos." }, 400);
  }
  const usuarioId = typeof body?.usuario_id === "string" ? body.usuario_id : "";
  if (!ID_VALIDO.test(usuarioId)) return responder({ ok: false, mensaje: "Datos inválidos." }, 400);

  const admin = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    { auth: { persistSession: false, autoRefreshToken: false } },
  );

  try {
    // 0) Límite por IP, además del bloqueo progresivo de cada cuenta: frena a
    //    quien pruebe muchas cuentas distintas desde un mismo lugar.
    const { data: permitido, error: eLimite } = await admin.rpc("fn_limite_clave", {
      p_clave: `login-ip:${ipDe(req)}`, p_max: MAX_INTENTOS_POR_IP, p_ventana_segundos: VENTANA_IP_SEGUNDOS,
    });
    if (eLimite) throw eLimite;
    if (!permitido) {
      return responder({ ok: false, bloqueado: true, segundos: 120, mensaje: "Demasiados intentos desde esta conexión. Espera unos minutos." }, 429);
    }

    // 1) La persona tiene que existir y estar activa en el negocio
    const { data: fila, error: eUsuarios } = await admin
      .from("app_data").select("value").eq("key", "usuarios").maybeSingle();
    if (eUsuarios) throw eUsuarios;
    const usuarios: any[] = Array.isArray(fila?.value) ? fila!.value : [];
    const usuario = usuarios.find((u) => u && u.id === usuarioId);
    if (!usuario || usuario.activo === false) {
      return responder({ ok: false, mensaje: "Esa persona no existe o está desactivada." });
    }

    // 2) Validar la clave, o la prueba de recuperación + guardar la clave nueva
    let resultado: any;
    if (body.restablecer) {
      const { metodo, prueba, bundle } = body.restablecer;
      if (!METODOS.has(metodo) || typeof prueba !== "string" || prueba.length > 200 || typeof bundle !== "object") {
        return responder({ ok: false, mensaje: "Datos inválidos." }, 400);
      }
      const { data, error } = await admin.rpc("fn_restablecer_clave", {
        p_usuario_id: usuarioId, p_metodo: metodo, p_prueba: prueba, p_bundle: bundle,
      });
      if (error) throw error;
      resultado = data;
    } else {
      const clave = typeof body.clave === "string" ? body.clave : "";
      if (!clave || clave.length > 200) return responder({ ok: false, mensaje: "Escribe tu clave." }, 400);
      const { data, error } = await admin.rpc("verificar_credencial", {
        p_usuario_id: usuarioId, p_tipo: "clave", p_valor: clave,
      });
      if (error) throw error;
      resultado = data;
    }
    // bloqueado / segundos / intentosRestantes / mensaje viajan tal cual a la pantalla
    if (!resultado?.ok) return responder({ ...resultado, ok: false });

    // 3) Usuario de Supabase Auth vinculado (se crea la primera vez)
    const email = correoInterno(usuarioId);
    const { error: eCrear } = await admin.auth.admin.createUser({
      email,
      email_confirm: true,
      app_metadata: { usuario_id: usuarioId },
    });
    if (eCrear && !/already|registered|exists/i.test(eCrear.message ?? "")) throw eCrear;

    // 4) Enlace mágico generado (no enviado): el navegador canjea su token_hash
    const { data: enlace, error: eEnlace } = await admin.auth.admin.generateLink({ type: "magiclink", email });
    if (eEnlace) throw eEnlace;
    if (enlace.user?.app_metadata?.usuario_id !== usuarioId) {
      throw new Error("El usuario de Auth no corresponde a esta persona.");
    }

    return responder({ ok: true, token_hash: enlace.properties.hashed_token });
  } catch (err) {
    console.error("iniciar-sesion:", err);
    return responder({ ok: false, errorServidor: true, mensaje: "No se pudo iniciar sesión. Intenta de nuevo." }, 500);
  }
});
