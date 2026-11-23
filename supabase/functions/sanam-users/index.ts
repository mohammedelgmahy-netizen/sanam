// Sanam admin: add, change and remove company users. Only a company admin may call it.
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

const URL_ = Deno.env.get("SUPABASE_URL")!;
const admin = createClient(URL_, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
const toEmail = (u: string) => u.trim().toLowerCase() + "@sanam.local";
const USER_RE = /^[a-z0-9._-]{3,30}$/;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const jwt = (req.headers.get("Authorization") || "").replace("Bearer ", "");
    const { data: who } = await admin.auth.getUser(jwt);
    if (!who?.user) return reply({ error: "سجل دخول الأول" }, 401);
    const { data: me } = await admin.from("sanam_members").select("*").eq("user_id", who.user.id).maybeSingle();
    if (!me || !me.is_admin || !me.active) return reply({ error: "الشاشة دي للمدير بس" }, 403);

    const b = await req.json();
    const fields = (x: any) => ({
      is_admin: !!x.is_admin,
      active: x.active !== false,
      requires_approval: !!x.requires_approval,
      permissions: x.permissions || {},
      allowed_projects: Array.isArray(x.allowed_projects) ? x.allowed_projects : null,
    });
    // the target must belong to the caller's company
    const mine = async (uid: string) => {
      const { data } = await admin.from("sanam_members").select("user_id").eq("user_id", uid).eq("company_id", me.company_id).maybeSingle();
      return !!data && uid !== me.user_id;
    };

    if (b.action === "create") {
      const username = String(b.username || "").trim().toLowerCase();
      if (!USER_RE.test(username)) return reply({ error: "اسم المستخدم لازم يكون بالإنجليزي أو أرقام، من ٣ لـ ٣٠ حرف، من غير مسافات" }, 400);
      if (String(b.password || "").length < 8) return reply({ error: "كلمة السر لازم تكون ٨ حروف على الأقل" }, 400);
      const { data: made, error } = await admin.auth.admin.createUser({ email: toEmail(username), password: b.password, email_confirm: true });
      if (error) return reply({ error: /registered|exists/i.test(error.message) ? "اسم المستخدم ده موجود قبل كده" : error.message }, 400);
      const { error: e2 } = await admin.from("sanam_members").insert({ company_id: me.company_id, user_id: made.user.id, username, ...fields(b) });
      if (e2) { await admin.auth.admin.deleteUser(made.user.id); return reply({ error: e2.message }, 400); }
      return reply({ ok: true, user_id: made.user.id });
    }
    if (b.action === "update") {
      if (!(await mine(b.user_id))) return reply({ error: "المستخدم ده مش موجود" }, 404);
      const { error } = await admin.from("sanam_members").update(fields(b)).eq("user_id", b.user_id);
      if (error) return reply({ error: error.message }, 400);
      if (b.password) {
        if (String(b.password).length < 8) return reply({ error: "كلمة السر لازم تكون ٨ حروف على الأقل" }, 400);
        const { error: e2 } = await admin.auth.admin.updateUserById(b.user_id, { password: b.password });
        if (e2) return reply({ error: e2.message }, 400);
      }
      return reply({ ok: true });
    }
    if (b.action === "delete") {
      if (!(await mine(b.user_id))) return reply({ error: "المستخدم ده مش موجود" }, 404);
      const { error } = await admin.auth.admin.deleteUser(b.user_id);
      if (error) return reply({ error: error.message }, 400);
      return reply({ ok: true });
    }
    return reply({ error: "unknown action" }, 400);
  } catch (e) {
    return reply({ error: String((e as Error).message || e) }, 500);
  }
});
