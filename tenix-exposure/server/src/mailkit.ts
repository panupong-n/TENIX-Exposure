// Every e-mail TENIX Exposure sends (invitations, password resets, alerts, tests) is built here, in ONE look: the one TENIX DeepSpace uses
// (a 600 px card on a light page, a dark header with the wordmark, a 4 px status rail, chips, a facts panel, one solid button with an Outlook fallback,
// a quiet footer that says why the mail arrived, a plain-text twin, a dark-mode palette, a hidden preheader).
// Fixed templates only: a caller passes values, never HTML. Every value is escaped here.
const esc = (v: unknown) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const clean = (v: unknown, n = 200) => String(v ?? "").replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, n);

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI','Helvetica Neue',Helvetica,Arial,'Leelawadee UI','Sukhumvit Set','Noto Sans Thai',Tahoma,sans-serif";
const MONO = "'IBM Plex Mono','SF Mono','Cascadia Mono',Consolas,'Liberation Mono','Courier New',monospace";
const HEADER_BG = "#0D1424", HEADER_BG2 = "#122036", TITANIUM = "#AAB7C5", CYAN = "#1EB8D8", OBSIDIAN = "#090D15";
const LIGHT = { page: "#EEF2F6", card: "#FFFFFF", panel: "#F4F7FA", line: "#E1E8EF", ink: "#0D1424", sub: "#3B4B5E", faint: "#566678", link: "#0B6E8A" };
const DARK = { page: "#090D15", card: "#0D1424", panel: "#162235", line: "#26354B", ink: "#F5F7FA", sub: "#C9D3DE", faint: "#8D9AAA", link: "#5FD6F5" };
// tone: [text on a light chip, light chip, text on a dark chip, dark chip, rail]
type Tone = "bad" | "warn" | "ok" | "info" | "dim";
const TONE: Record<Tone, [string, string, string, string, string]> = {
  bad: ["#B42318", "#FDECEA", "#FF8F93", "#3A171B", "#E5484D"],
  warn: ["#8A4B00", "#FFF1D0", "#FFC46B", "#38280F", "#F0A63A"],
  ok: ["#12663F", "#E2F5EC", "#6FE3A3", "#10332A", "#3CCF7E"],
  info: ["#0B6E8A", "#E0F4F9", "#7FE0FF", "#0E3141", CYAN],
  dim: ["#445568", "#E8EDF2", "#C9D3DE", "#22324A", "#8D9AAA"],
};
export const BRAND = "10CYBER EXPOSURE";

function darkRules(): string {
  const d = DARK;
  const base: Record<string, string> = {
    ".em-page": `background-color:${d.page} !important`,
    ".em-card": `background-color:${d.card} !important;border-color:${d.line} !important`,
    ".em-panel": `background-color:${d.panel} !important;border-color:${d.line} !important`,
    ".em-line": `border-color:${d.line} !important`,
    ".em-ink": `color:${d.ink} !important`, ".em-sub": `color:${d.sub} !important`, ".em-faint": `color:${d.faint} !important`, ".em-link": `color:${d.link} !important`,
    ".em-btn": `color:${OBSIDIAN} !important`,
  };
  for (const [t, v] of Object.entries(TONE)) base[`.em-c-${t}`] = `background-color:${v[3]} !important;color:${v[2]} !important`;
  const css = Object.entries(base).map(([s, decl]) => `${s}{${decl}}`).join("");
  const ogs = Object.entries(base).map(([s, decl]) => `[data-ogsc] ${s},[data-ogsb] ${s}{${decl}}`).join("");
  return `@media (prefers-color-scheme:dark){${css}}${ogs}`;
}
const headCss = () =>
  "body,table,td,a{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%}table,td{mso-table-lspace:0pt;mso-table-rspace:0pt}img{-ms-interpolation-mode:bicubic}a{text-decoration:none}" +
  "@media screen and (max-width:480px){.em-px{padding-left:20px !important;padding-right:20px !important}.em-h1{font-size:22px !important;line-height:1.28 !important}" +
  ".em-hide-m{display:none !important;max-height:0 !important;overflow:hidden !important}.em-lbl{width:96px !important}.em-btn-w{width:100% !important}.em-outer{padding:12px 8px 24px !important}}" + darkRules();

const chip = (text: string, tone: Tone = "info") =>
  `<span class="em-c-${tone}" style="display:inline-block;padding:4px 10px;border-radius:999px;background-color:${TONE[tone][1]};color:${TONE[tone][0]};font-weight:600;font-size:12px;line-height:1.2;letter-spacing:.03em;white-space:nowrap">${esc(text)}</span>`;
const chips = (...pairs: [string, Tone][]) => `<span style="font-size:0;font-family:${FONT}">${pairs.map(([t, k]) => `<span style="display:inline-block;padding:0 6px 6px 0">${chip(t, k)}</span>`).join("")}</span>`;

/** A table button with a VML twin (Outlook desktop ignores padding on a link). Cyan, dark text: readable in both colour schemes. */
function button(href: string, label: string): string {
  const h = esc(href), lb = esc(label), w = Math.min(320, Math.max(200, 40 + 9 * label.length));
  return `<!--[if mso]><v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="${h}" style="height:48px;v-text-anchor:middle;width:${w}px" arcsize="21%" strokecolor="${CYAN}" fillcolor="${CYAN}"><w:anchorlock/><center style="color:${OBSIDIAN};font-family:Segoe UI,Arial,sans-serif;font-size:15px;font-weight:bold">${lb}</center></v:roundrect><![endif]-->` +
    `<!--[if !mso]><!--><table role="presentation" cellpadding="0" cellspacing="0" border="0" class="em-btn-w"><tr><td align="center" bgcolor="${CYAN}" style="border-radius:10px;background-color:${CYAN}">` +
    `<a href="${h}" class="em-btn" style="display:inline-block;padding:14px 28px;min-width:184px;border-radius:10px;font:700 15px/20px ${FONT};color:${OBSIDIAN};text-decoration:none;text-align:center">${lb}</a></td></tr></table><!--<![endif]-->`;
}

/** Facts in a light panel: label left (13 px), value right (15 px, bold). */
function facts(rows: [string, string][]): string {
  const body = rows.map(([k, v], i) => {
    const line = i === rows.length - 1 ? "" : `border-bottom:1px solid ${LIGHT.line};`;
    return `<tr><td class="em-lbl em-faint em-line" valign="top" style="width:128px;padding:12px 12px 10px 0;${line}font:13px/1.5 ${FONT};color:${LIGHT.faint}">${esc(k)}</td>` +
      `<td class="em-ink em-line" valign="top" style="padding:10px 0;${line}font:600 15px/1.5 ${FONT};color:${LIGHT.ink};word-break:break-word">${esc(v)}</td></tr>`;
  }).join("");
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="em-panel" bgcolor="${LIGHT.panel}" style="background-color:${LIGHT.panel};border:1px solid ${LIGHT.line};border-radius:10px"><tr><td style="padding:6px 18px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0">${body}</table></td></tr></table>`;
}
const row = (inner: string, top = 0, bottom = 0) => `<tr><td class="em-px" style="padding:${top}px 40px ${bottom}px">${inner}</td></tr>`;
const para = (html: string, top = 0, bottom = 18, small = false) => row(`<div class="em-${small ? "faint" : "sub"}" style="font:${small ? "14px/1.6" : "16px/1.65"} ${FONT};color:${small ? LIGHT.faint : LIGHT.sub}">${html}</div>`, top, bottom);
const strong = (t: string) => `<strong class="em-ink" style="color:${LIGHT.ink}">${esc(t)}</strong>`;
const copyLink = (link: string, lead: string, bottom = 28) =>
  para(`${esc(lead)}<br><span class="em-link" style="word-break:break-all;font-family:${MONO};font-size:12.5px;color:${LIGHT.link}">${esc(link)}</span>`, 0, bottom, true);

const header = (label: string) =>
  `<tr><td bgcolor="${HEADER_BG}" class="em-px" style="padding:26px 40px;background-color:${HEADER_BG};background-image:linear-gradient(135deg,${HEADER_BG} 0%,${HEADER_BG2} 100%);border-radius:12px 12px 0 0">` +
  `<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>` +
  `<td valign="middle" style="font:800 20px/1 ${FONT};letter-spacing:.14em;color:#F5F7FA;white-space:nowrap">10CYBER</td>` +
  `<td valign="middle" style="padding-left:14px;font:600 11px/1 ${FONT};letter-spacing:.34em;color:${TITANIUM};white-space:nowrap">BY TENFORWARD</td>` +
  `<td valign="middle" align="right" class="em-hide-m" style="font:600 11px/1 ${FONT};letter-spacing:.16em;color:${TITANIUM};text-transform:uppercase;white-space:nowrap">${esc(label)}</td>` +
  `</tr></table></td></tr>`;
const rail = (tone: Tone) => `<tr><td height="4" bgcolor="${TONE[tone][4]}" style="height:4px;line-height:4px;font-size:0;background-color:${TONE[tone][4]}">&nbsp;</td></tr>`;
const footer = (reason: string) =>
  `<tr><td class="em-px" style="padding:0 40px 32px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="em-line" style="border-top:1px solid ${LIGHT.line}">` +
  `<tr><td class="em-faint" style="padding:22px 0 12px;font:600 11px/1 ${FONT};letter-spacing:.14em;color:${LIGHT.faint}">${BRAND}</td></tr>` +
  `<tr><td class="em-faint" style="font:12.5px/1.65 ${FONT};color:${LIGHT.faint}">${esc(reason)}</td></tr>` +
  `<tr><td class="em-faint" style="padding-top:10px;font:12px/1.5 ${FONT};color:${LIGHT.faint}">© ${new Date().getFullYear()} 10CYBER · TENFORWARD. All rights reserved.</td></tr></table></td></tr>`;

function wrap(o: { title: string; rows: string; reason: string; label: string; lead?: string; tone?: Tone; chips?: string; preheader?: string }): string {
  const lead = o.lead ? `<div class="em-sub" style="padding-top:10px;font:16px/1.6 ${FONT};color:${LIGHT.sub}">${esc(o.lead)}</div>` : "";
  const pad = "&#847;&zwnj;&nbsp;".repeat(40); // keeps the next mail's first line out of the preheader
  return `<!doctype html><html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="x-apple-disable-message-reformatting"><meta name="format-detection" content="telephone=no,date=no,address=no,email=no,url=no">` +
    `<meta name="color-scheme" content="light dark"><meta name="supported-color-schemes" content="light dark">` +
    `<!--[if mso]><noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript><![endif]-->` +
    `<title>${esc(o.title)}</title><style>${headCss()}</style></head>` +
    `<body class="em-page" bgcolor="${LIGHT.page}" style="margin:0;padding:0;width:100%;background-color:${LIGHT.page};color:${LIGHT.ink}">` +
    `<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:1px;line-height:1px;color:${LIGHT.page};opacity:0">${esc(o.preheader || o.lead || o.title)}${pad}</div>` +
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="em-page" bgcolor="${LIGHT.page}" style="background-color:${LIGHT.page}"><tr><td align="center" class="em-outer" style="padding:28px 12px 40px">` +
    `<table role="presentation" width="600" cellpadding="0" cellspacing="0" class="em-card" bgcolor="${LIGHT.card}" style="width:100%;max-width:600px;background-color:${LIGHT.card};border:1px solid ${LIGHT.line};border-radius:12px;border-collapse:separate">` +
    `${header(o.label)}${rail(o.tone ?? "info")}` +
    `<tr><td class="em-px" style="padding:32px 40px 22px">${o.chips ? `<div style="padding-bottom:8px">${o.chips}</div>` : ""}` +
    `<h1 class="em-h1 em-ink" style="margin:0;font:700 26px/1.25 ${FONT};letter-spacing:-.01em;color:${LIGHT.ink}">${esc(o.title)}</h1>${lead}</td></tr>` +
    `${o.rows}${footer(o.reason)}</table></td></tr></table></body></html>`;
}

export interface Mail { subject: string; text: string; html: string }
const hours = (ms: number) => { const h = Math.round(ms / 3600_000); return h >= 48 && h % 24 === 0 ? `${h / 24} days` : `${h} hour${h === 1 ? "" : "s"}`; };
const IGNORE = "If you were not expecting this email, you can ignore it.";

export function composeInvite(p: { name?: string | null; inviter: string; role: string; organizations: string[]; link: string; ttlMs: number }): Mail {
  const inviter = clean(p.inviter, 100), link = p.link;
  const f: [string, string][] = [["Invited by", inviter], ["Your role", clean(p.role, 60) || "—"]];
  if (p.organizations.length) f.push(["Organizations", p.organizations.map((o) => clean(o, 80)).join(", ")]);
  f.push(["Link valid for", `${hours(p.ttlMs)}, one use`]);
  const rows = para(`Hello${p.name ? ` ${strong(clean(p.name, 100))}` : ""} — ${strong(inviter)} invited you to 10CYBER Exposure.`, 4, 22) + row(facts(f), 0, 22) +
    row(button(link, "Set a password and sign in"), 0, 22) + copyLink(link, "If the button does not work, copy this link into your browser:");
  const reason = `Sent by ${BRAND} because ${inviter} invited you. ${IGNORE}`;
  return {
    subject: "[10CYBER Exposure] You have been invited",
    text: `Hello${p.name ? ` ${clean(p.name, 100)}` : ""},\n\n${inviter} invited you to 10CYBER Exposure.\n${f.map(([k, v]) => `${k}: ${v}`).join("\n")}\n\nSet a password and sign in: ${link}\nThe link works once, for ${hours(p.ttlMs)}.\n\n${reason}\n`,
    html: wrap({ title: "You are invited", rows, reason, label: "Security", lead: "10CYBER Exposure", chips: chips(["Invitation", "info"]), preheader: `${inviter} invited you to 10CYBER Exposure. The link works for ${hours(p.ttlMs)}.` }),
  };
}

export function composeReset(p: { name?: string | null; byAdmin: boolean; link: string; ttlMs: number }): Mail {
  const who = p.byAdmin ? "An administrator requested a password reset for your account" : "We received a password reset request for your account";
  const ignore = "If you did not ask for this, ignore this email — your current password still works.";
  const rows = para(`Hello${p.name ? ` ${strong(clean(p.name, 100))}` : ""} — ${esc(who.toLowerCase())}.`, 4, 22) + row(facts([["Link valid for", `${hours(p.ttlMs)}, one use`]]), 0, 22) +
    row(button(p.link, "Set a new password"), 0, 22) + copyLink(p.link, "If the button does not work, copy this link into your browser:", 14) + para(esc(ignore), 0, 28, true);
  const reason = `Sent by ${BRAND} about your account. ${IGNORE}`;
  return {
    subject: "[10CYBER Exposure] Set a new password",
    text: `Hello${p.name ? ` ${clean(p.name, 100)}` : ""},\n\n${who}.\nSet a new password: ${p.link}\nThe link works once, for ${hours(p.ttlMs)}.\n${ignore}\n\n${reason}\n`,
    html: wrap({ title: "Set a new password", rows, reason, label: "Security", lead: "10CYBER Exposure", chips: chips(["Password reset", "info"]), preheader: `Use this link within ${hours(p.ttlMs)} to set a new password.` }),
  };
}

const REASON_ALERT = `Sent automatically by ${BRAND} because you are on its alert list.`;
export function composeSyncFailed(p: { organization: string; state: string; link: string }): Mail {
  const org = clean(p.organization, 100), state = clean(p.state, 20);
  const tone: Tone = state === "failed" ? "bad" : "warn";
  const rows = para(`The latest data sync for ${strong(org)} did not finish completely. The numbers in ${BRAND} may be incomplete until the next successful sync.`, 4, 22) +
    row(facts([["Organization", org], ["Sync result", state]]), 0, 22) + row(button(p.link, "Open 10CYBER Exposure"), 0, 28);
  return {
    subject: `[10CYBER Exposure] Data sync ${state}: ${org}`,
    text: `The latest data sync for ${org} did not finish completely (${state}).\nThe numbers in ${BRAND} may be incomplete until the next successful sync.\n\n${p.link}\n\n${REASON_ALERT}\n`,
    html: wrap({ title: `Data sync ${state}`, rows, reason: REASON_ALERT, label: "Alert", lead: org, tone, chips: chips([state === "failed" ? "Sync failed" : "Sync incomplete", tone]), preheader: `The latest data sync for ${org} was ${state}.` }),
  };
}

export function composeCritical(p: { organization: string; cves: string[]; devices: number; link: string }): Mail {
  const org = clean(p.organization, 100), n = p.cves.length;
  const listed = p.cves.slice(0, 10).map((c) => clean(c, 40));
  const f: [string, string][] = [["Organization", org], ["New critical", `${n} vulnerabilit${n === 1 ? "y" : "ies"}`], ["Devices", String(p.devices)]];
  const list = `<div class="em-ink" style="font:600 14px/1.9 ${MONO};color:${LIGHT.ink}">${listed.map(esc).join("<br>")}${n > listed.length ? `<br><span class="em-faint" style="font:13px/1.6 ${FONT};color:${LIGHT.faint}">… and ${n - listed.length} more</span>` : ""}</div>`;
  const rows = para(`${strong(`${n} new critical vulnerabilit${n === 1 ? "y was" : "ies were"}`)} found on ${p.devices} device${p.devices === 1 ? "" : "s"} at ${strong(org)}.`, 4, 22) +
    row(facts(f), 0, 18) + row(list, 0, 24) + row(button(p.link, "See the details"), 0, 28);
  return {
    subject: `[10CYBER Exposure] ${n} new critical vulnerabilit${n === 1 ? "y" : "ies"}: ${org}`,
    text: `${n} new critical vulnerabilit${n === 1 ? "y was" : "ies were"} found on ${p.devices} device${p.devices === 1 ? "" : "s"} at ${org}.\n\n${listed.join("\n")}${n > listed.length ? `\n… and ${n - listed.length} more` : ""}\n\n${p.link}\n\n${REASON_ALERT}\n`,
    html: wrap({ title: `${n} new critical vulnerabilit${n === 1 ? "y" : "ies"}`, rows, reason: REASON_ALERT, label: "Alert", lead: org, tone: "bad", chips: chips(["Critical", "bad"]), preheader: `${n} new critical on ${p.devices} device${p.devices === 1 ? "" : "s"} at ${org}.` }),
  };
}

export function composeTest(p: { sender: string }): Mail {
  const rows = para(`This test message was sent by ${BRAND} using the sender ${strong(clean(p.sender, 80))}. Invitations, password-reset links and alerts are delivered the same way.`, 4, 34);
  const reason = `Sent by ${BRAND} to test the e-mail sender. No action is needed.`;
  return {
    subject: "[10CYBER Exposure] Test email",
    text: `This test message was sent by ${BRAND} using the sender ${clean(p.sender, 80)}. Your sender settings work.\n\n${reason}\n`,
    html: wrap({ title: "Email delivery works", rows, reason, label: "Test", lead: "10CYBER Exposure", tone: "ok", chips: chips(["Test message", "ok"]) }),
  };
}
