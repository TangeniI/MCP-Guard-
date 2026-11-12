// MCP Guard approval page.
//
// Everything shown here that came from an agent (tool names, arguments) is
// untrusted. It is only ever placed with textContent, never as HTML.
"use strict";

const $ = (id) => document.getElementById(id);
const statusEl = $("status");
const signin = $("signin");
const queue = $("queue");
const list = $("pending");
const empty = $("empty");

let token = "";
let timer = null;

try { token = sessionStorage.getItem("mcpguard-approver-token") || ""; } catch (_) { /* storage blocked */ }

function setStatus(text) { statusEl.textContent = text; }

function signOut(message) {
  token = "";
  try { sessionStorage.removeItem("mcpguard-approver-token"); } catch (_) {}
  clearTimeout(timer);
  list.replaceChildren();
  queue.hidden = true;
  signin.hidden = false;
  setStatus(message || "Signed out.");
}

async function api(method, path) {
  const res = await fetch(path, { method, headers: { Authorization: "Bearer " + token }, cache: "no-store" });
  if (res.status === 401) { signOut("That token was not accepted."); throw new Error("unauthorized"); }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || "Request failed (" + res.status + ")");
  return body;
}

function prettyArguments(args) {
  try { return JSON.stringify(args, null, 2); } catch (_) { return String(args); }
}

function secondsLeft(expires) {
  return Math.max(0, Math.round((new Date(expires).getTime() - Date.now()) / 1000));
}

function render(pending) {
  empty.hidden = pending.length > 0;
  const items = pending.map((req) => {
    const li = document.createElement("li");

    const title = document.createElement("h2");
    title.textContent = req.tool + " on " + req.server;

    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent = "Agent " + req.agent + " · refused automatically in " + secondsLeft(req.expires) + "s";

    const args = document.createElement("pre");
    args.textContent = prettyArguments(req.arguments);

    const actions = document.createElement("div");
    actions.className = "actions";
    for (const action of ["deny", "approve"]) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = action;
      button.textContent = action === "approve" ? "Approve this call" : "Deny";
      button.addEventListener("click", () => decide(req.id, action, actions));
      actions.append(button);
    }

    li.append(title, meta, args, actions);
    return li;
  });
  list.replaceChildren(...items);
}

async function decide(id, action, actions) {
  for (const b of actions.querySelectorAll("button")) b.disabled = true;
  try {
    await api("POST", "api/approvals/" + encodeURIComponent(id) + "/" + action);
    setStatus(action === "approve" ? "Approved." : "Denied.");
  } catch (err) {
    if (token) setStatus(err.message);
  }
  if (token) refresh();
}

async function refresh() {
  clearTimeout(timer);
  if (!token) return;
  try {
    const data = await api("GET", "api/approvals");
    signin.hidden = true;
    queue.hidden = false;
    if (statusEl.textContent.startsWith("Enter") || statusEl.textContent.startsWith("Checking")) {
      setStatus("Signed in as " + data.approver + ". Calls are refused after " + data.timeout_seconds + "s without a decision.");
    }
    render(data.pending);
  } catch (err) {
    if (!token) return;
    setStatus("Could not reach the gateway: " + err.message);
  }
  timer = setTimeout(refresh, 2000);
}

signin.addEventListener("submit", (event) => {
  event.preventDefault();
  token = $("token").value.trim();
  $("token").value = "";
  if (!token) return;
  try { sessionStorage.setItem("mcpguard-approver-token", token); } catch (_) {}
  setStatus("Checking token…");
  refresh();
});

$("signout").addEventListener("click", () => signOut());

if (token) { setStatus("Checking token…"); refresh(); }
