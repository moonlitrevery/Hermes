// Hermes UI. All crypto and networking happen in Rust; this file only renders
// what the backend returns. User-controlled strings are inserted with
// textContent, never innerHTML.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

const state = {
  profile: null,
  groups: [],
  active: null,
  messages: new Map(), // groupId -> ChatMessage[] sorted by id
  hasOlder: new Map(), // groupId -> bool
  unread: new Map(),
};

// ---------- dialog ----------

function dialog({ title, text = "", input = null, code = null, ok = "OK", cancel = true, onOk }) {
  const d = $("dialog");
  $("dialog-title").textContent = title;
  $("dialog-text").textContent = text;
  $("dialog-error").textContent = "";
  $("dialog-input").hidden = !input;
  $("dialog-code").hidden = code == null;
  $("dialog-code").textContent = code ?? "";
  $("dialog-cancel").hidden = !cancel;
  $("dialog-ok").textContent = ok;
  if (input) {
    $("dialog-input").value = input.value ?? "";
    $("dialog-input").placeholder = input.placeholder ?? "";
    $("dialog-input").maxLength = input.maxLength ?? 200;
  }

  return new Promise((resolve) => {
    const form = $("dialog-form");
    const finish = (result) => {
      form.onsubmit = null;
      $("dialog-cancel").onclick = null;
      d.oncancel = null;
      d.close();
      resolve(result);
    };
    form.onsubmit = async (e) => {
      e.preventDefault();
      const value = input ? $("dialog-input").value : null;
      $("dialog-ok").disabled = true;
      try {
        finish(onOk ? await onOk(value) : value);
      } catch (err) {
        $("dialog-error").textContent = String(err);
      } finally {
        $("dialog-ok").disabled = false;
      }
    };
    $("dialog-cancel").onclick = () => finish(undefined);
    d.oncancel = (e) => {
      if (!cancel) e.preventDefault();
      else finish(undefined);
    };
    d.showModal();
    if (input) $("dialog-input").focus();
  });
}

let bannerTimer;
function banner(message) {
  const b = $("banner");
  b.textContent = message;
  b.hidden = false;
  clearTimeout(bannerTimer);
  bannerTimer = setTimeout(() => (b.hidden = true), 5000);
}

async function call(cmd, args) {
  try {
    return await invoke(cmd, args);
  } catch (err) {
    banner(String(err));
    throw err;
  }
}

// ---------- profile ----------

function renderProfile() {
  $("profile-name").textContent = state.profile.display_name || "Set your name";
  $("profile-fp").textContent = state.profile.fingerprint;
  $("profile-chip").title = "Your key fingerprint. Friends can compare it to verify it's really you.";
}

async function editName(required = false) {
  const profile = await dialog({
    title: required ? "Welcome to Hermes" : "Display name",
    text: "Your name is encrypted inside every message. The server never sees it.",
    input: { value: state.profile.display_name, placeholder: "Your name", maxLength: 64 },
    ok: "Save",
    cancel: !required,
    onOk: (name) => invoke("set_display_name", { name }),
  });
  if (profile) {
    state.profile = profile;
    renderProfile();
  }
}

// ---------- groups ----------

function renderGroups() {
  const nav = $("groups");
  nav.replaceChildren(
    ...state.groups.map((g) => {
      const b = el("button", "group" + (g.id === state.active ? " active" : ""));
      b.type = "button";
      b.append(el("span", "group-name", g.name));
      const n = state.unread.get(g.id) || 0;
      if (n) b.append(el("span", "badge", n > 99 ? "99+" : String(n)));
      b.onclick = () => openGroup(g.id);
      return b;
    }),
  );
  $("groups-empty").hidden = state.groups.length > 0;
}

function addGroup(group) {
  state.groups.push(group);
  renderGroups();
  openGroup(group.id);
}

async function createGroup() {
  const group = await dialog({
    title: "New group",
    input: { placeholder: "Group name", maxLength: 64 },
    ok: "Create",
    onOk: (name) => invoke("create_group", { name }),
  });
  if (group) {
    addGroup(group);
    showInvite(group);
  }
}

async function joinGroup() {
  const group = await dialog({
    title: "Join a group",
    text: "Paste the invite code a member shared with you.",
    input: { placeholder: "Invite code", maxLength: 200 },
    ok: "Join",
    onOk: (invite) => invoke("join_group", { invite }),
  });
  if (group) addGroup(group);
}

function showInvite(group) {
  dialog({
    title: `Invite to ${group.name}`,
    text: "Anyone with this code can join and read the whole group, so share it only with people you trust, over a channel you trust.",
    code: group.invite,
    ok: "Copy",
    onOk: async () => {
      await navigator.clipboard.writeText(group.invite);
      banner("Invite code copied.");
    },
  });
}

async function leaveGroup() {
  const group = state.groups.find((g) => g.id === state.active);
  if (!group) return;
  const confirmed = await dialog({
    title: `Leave ${group.name}?`,
    text: "This removes the group and its key from this device. You'll need the invite code again to rejoin.",
    ok: "Leave",
    onOk: () => invoke("leave_group", { groupId: group.id }).then(() => true),
  });
  if (!confirmed) return;
  state.groups = state.groups.filter((g) => g.id !== group.id);
  state.messages.delete(group.id);
  state.active = null;
  renderGroups();
  showChat(false);
}

// ---------- chat ----------

function showChat(show) {
  $("chat-view").hidden = !show;
  $("chat-placeholder").hidden = show;
  $("app").classList.toggle("in-chat", show);
}

async function openGroup(id) {
  const group = state.groups.find((g) => g.id === id);
  if (!group) return;
  state.active = id;
  state.unread.delete(id);
  renderGroups();
  $("chat-title").textContent = group.name;
  showChat(true);
  renderMessages(true);
  if (!state.messages.has(id)) {
    const page = await call("history", { groupId: id, beforeId: null });
    state.hasOlder.set(id, page.length >= 50);
    mergeMessages(id, page);
    if (state.active === id) renderMessages(true);
  }
  $("input").focus();
}

async function loadOlder() {
  const id = state.active;
  const list = state.messages.get(id) || [];
  if (!list.length) return;
  const box = $("messages");
  const before = box.scrollHeight;
  const page = await call("history", { groupId: id, beforeId: list[0].id });
  state.hasOlder.set(id, page.length >= 50);
  mergeMessages(id, page);
  renderMessages(false);
  box.scrollTop = box.scrollHeight - before;
}

function mergeMessages(groupId, incoming) {
  const list = state.messages.get(groupId) || [];
  const seen = new Set(list.map((m) => m.id));
  let added = 0;
  for (const m of incoming) {
    if (!seen.has(m.id)) {
      list.push(m);
      seen.add(m.id);
      added++;
    }
  }
  list.sort((a, b) => a.id - b.id);
  state.messages.set(groupId, list);
  return added;
}

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const dayFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

function renderMessages(scrollToEnd) {
  const box = $("messages");
  const list = state.messages.get(state.active) || [];
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  const older = $("load-older");
  older.hidden = !state.hasOlder.get(state.active);

  const nodes = [];
  let prev = null;
  for (const m of list) {
    const when = new Date(m.created_at);
    if (!prev || new Date(prev.created_at).toDateString() !== when.toDateString()) {
      nodes.push(el("div", "hint day", dayFmt.format(when)));
      prev = null;
    }
    const grouped = prev && prev.sender_fingerprint === m.sender_fingerprint && prev.sender_name === m.sender_name;
    const bubble = el("div", "msg" + (m.mine ? " mine" : "") + (grouped ? " grouped" : ""));
    if (!m.mine && !grouped) {
      const meta = el("div", "msg-meta");
      meta.append(el("span", "msg-sender", m.sender_name || "Unnamed"), el("span", "fingerprint", m.sender_fingerprint));
      bubble.append(meta);
    }
    bubble.append(el("div", "msg-text", m.text), el("div", "msg-time", timeFmt.format(when)));
    nodes.push(bubble);
    prev = m;
  }
  box.replaceChildren(older, ...nodes);
  if (scrollToEnd || nearBottom) box.scrollTop = box.scrollHeight;
}

async function send(e) {
  e.preventDefault();
  const input = $("input");
  const text = input.value.trim();
  if (!text || !state.active) return;
  const groupId = state.active;
  input.value = "";
  autosize();
  try {
    const msg = await call("send_message", { groupId, text });
    mergeMessages(groupId, [msg]);
    if (state.active === groupId) renderMessages(true);
  } catch {
    input.value = text; // keep the draft so nothing is lost
    autosize();
  }
}

function autosize() {
  const t = $("input");
  t.style.height = "auto";
  t.style.height = Math.min(t.scrollHeight, 160) + "px";
}

// ---------- live events ----------

function onEvent({ payload }) {
  const status = $("status");
  switch (payload.kind) {
    case "online":
      status.className = "status online";
      status.title = "Connected";
      break;
    case "offline":
      status.className = "status offline";
      status.title = "Reconnecting… (" + payload.reason + ")";
      break;
    case "message": {
      const m = payload.message;
      if (!state.groups.some((g) => g.id === m.group_id)) return;
      // Groups never opened are fetched in full when first opened.
      if (!state.messages.has(m.group_id) && m.group_id !== state.active) {
        if (!m.mine) state.unread.set(m.group_id, (state.unread.get(m.group_id) || 0) + 1);
        renderGroups();
        return;
      }
      const added = mergeMessages(m.group_id, [m]);
      if (m.group_id === state.active) renderMessages(false);
      else if (added && !m.mine) {
        state.unread.set(m.group_id, (state.unread.get(m.group_id) || 0) + 1);
        renderGroups();
      }
    }
  }
}

// ---------- boot ----------

async function boot() {
  $("new-group").onclick = createGroup;
  $("join-group").onclick = joinGroup;
  $("profile-chip").onclick = () => editName(false);
  $("show-invite").onclick = () => showInvite(state.groups.find((g) => g.id === state.active));
  $("leave").onclick = leaveGroup;
  $("back").onclick = () => {
    state.active = null;
    renderGroups();
    showChat(false);
  };
  $("load-older").onclick = loadOlder;
  $("composer").onsubmit = send;
  $("input").addEventListener("input", autosize);
  $("input").addEventListener("keydown", (e) => {
    // Enter sends, Shift+Enter adds a newline (on touch keyboards Enter inserts a newline).
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing && !matchMedia("(pointer: coarse)").matches) {
      e.preventDefault();
      $("composer").requestSubmit();
    }
  });

  await listen("hermes", onEvent);
  state.profile = await invoke("profile");
  state.groups = await invoke("list_groups");
  renderProfile();
  renderGroups();

  if (!state.profile.configured) {
    $("status").className = "status offline";
    $("status").title = "Not configured";
    await dialog({
      title: "Backend not configured",
      text: "This build has no Supabase project. Rebuild with HERMES_SUPABASE_URL and HERMES_SUPABASE_ANON_KEY set (see README).",
      ok: "OK",
      cancel: false,
    });
  }
  if (!state.profile.display_name) await editName(true);
}

boot();
