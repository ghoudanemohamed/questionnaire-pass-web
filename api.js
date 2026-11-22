// Appelle les fonctions de la base (schema.sql) via l'API REST de Supabase.
async function rpc(name, args) {
  const c = window.SB_CONFIG || {};
  if (!c.url || c.url.includes("VOTRE-PROJET")) throw new Error("Site non configuré : remplis config.js");
  const headers = { "Content-Type": "application/json", apikey: c.key };
  if (String(c.key).startsWith("eyJ")) headers.Authorization = "Bearer " + c.key; // anciennes clés (JWT)
  const r = await fetch(c.url.replace(/\/$/, "") + "/rest/v1/rpc/" + name, {
    method: "POST", headers, body: JSON.stringify(args || {})
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    throw new Error(e.message || "Erreur " + r.status);
  }
  return r.json();
}
