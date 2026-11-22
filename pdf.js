// Pass en PDF avec QR code, fabriqué dans le navigateur (jsPDF + qrcode-generator).
// a = { code, role, first, last, company, expires }  ; le QR code ouvre pass.html?c=<code>
function passUrl(code) {
  return new URL("pass.html?c=" + encodeURIComponent(code), location.href).href;
}

function makePassPdf(a) {
  if (!window.jspdf || !window.qrcode) throw new Error("Outils PDF non chargés : vérifie ta connexion internet");
  const doc = new window.jspdf.jsPDF({ unit: "mm", format: "a5" });
  const W = 148, violet = [109, 40, 217], ink = [27, 16, 48], muted = [107, 98, 128];
  const intervenant = a.role === "intervenant";

  doc.setFillColor(...violet); doc.rect(0, 0, W, 32, "F");
  doc.setTextColor(255, 255, 255); doc.setFont("helvetica", "bold"); doc.setFontSize(24);
  doc.text(intervenant ? "Pass intervenant" : "Pass visiteur", 12, 21);

  doc.setTextColor(...ink); doc.setFontSize(20);
  doc.text(`${a.first} ${a.last}`.slice(0, 34), 12, 52);
  doc.setFont("helvetica", "normal"); doc.setFontSize(13); doc.setTextColor(...muted);
  doc.text(String(a.company || "").slice(0, 46), 12, 60);

  const qr = window.qrcode(0, "M");
  qr.addData(passUrl(a.code)); qr.make();
  const n = qr.getModuleCount(), size = 68, cell = size / n, x0 = (W - size) / 2, y0 = 74;
  doc.setFillColor(0, 0, 0);
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++)
    if (qr.isDark(r, c)) doc.rect(x0 + c * cell, y0 + r * cell, cell + 0.03, cell + 0.03, "F");

  doc.setFontSize(9); doc.setTextColor(...muted);
  doc.text("Scanne ce QR code pour vérifier que le pass est valable", W / 2, y0 + size + 8, { align: "center" });
  doc.setFont("courier", "bold"); doc.setFontSize(22); doc.setTextColor(...ink);
  doc.text(a.code, W / 2, 184, { align: "center" });
  doc.setFont("helvetica", "normal"); doc.setFontSize(9); doc.setTextColor(...muted);
  doc.text("Code personnel · valable jusqu'au " + new Date(a.expires).toLocaleDateString("fr-FR"), W / 2, 193, { align: "center" });
  doc.save("pass-" + a.code + ".pdf");
}
