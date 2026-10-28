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

const ROLE_LABEL = { owner: "Owner", admin: "Admin", member: "Member" };

const state = {
  profile: null,
  groups: [],
  pending: [], // group ids waiting for an admin
  active: null,
  messages: new Map(), // groupId -> ChatMessage[]
  unread: new Map(),
  draft: null, // { groupId, id, text } of a send whose outcome is unknown
};

const activeGroup = () => state.groups.find((g) => g.id === state.active);

// ---------- dialog ----------

function dialog({ title, text = "", input = null, code = null, body = null, ok = "OK", cancel = true, onOk }) {
  const d = $("dialog");
  $("dialog-title").textContent = title;
  $("dialog-text").textContent = text;
  $("dialog-error").textContent = "";
  $("dialog-input").hidden = !input;
  $("dialog-code").hidden = code == null;
  $("dialog-code").textContent = code ?? "";
  $("dialog-body").replaceChildren(...(body ? [body] : []));
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
  bannerTimer = setTimeout(() => (b.hidden = true), 6000);
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
    text: "Your name travels encrypted inside your messages. The server never sees it.",
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

async function reloadGroups() {
  state.groups = await invoke("list_groups");
  state.pending = await invoke("pending_joins");
  renderGroups();
  if (state.active) {
    if (activeGroup()) renderChatChrome();
    else closeChat();
  }
}

function renderGroups() {
  const nav = $("groups");
  nav.replaceChildren(
    ...state.groups.map((g) => {
      const b = el("button", "group" + (g.id === state.active ? " active" : "") + (g.removed ? " removed" : ""));
      b.type = "button";
      b.append(el("span", "group-name", g.name));
      if (g.removed) b.append(el("span", "tag", "removed"));
      else if (g.role !== "member") b.append(el("span", "tag", ROLE_LABEL[g.role]));
      const n = state.unread.get(g.id) || 0;
      if (n) b.append(el("span", "badge", n > 99 ? "99+" : String(n)));
      b.onclick = () => openGroup(g.id);
      return b;
    }),
  );
  $("pending").replaceChildren(
    ...state.pending
      .filter((id) => !state.groups.some((g) => g.id === id))
      .map(() => el("p", "pending-item", "Waiting for an admin to let you in…")),
  );
  $("groups-empty").hidden = state.groups.length > 0 || state.pending.length > 0;
}

async function createGroup() {
  const group = await dialog({
    title: "New group",
    input: { placeholder: "Group name", maxLength: 64 },
    ok: "Create",
    onOk: (name) => invoke("create_group", { name }),
  });
  if (group) {
    await reloadGroups();
    openGroup(group.id);
  }
}

async function joinGroup() {
  const joined = await dialog({
    title: "Join a group",
    text: "Enter the code an admin shared with you. It works once and only for 5 minutes. An admin's Hermes lets you in automatically.",
    input: { placeholder: "XXXX-XXXX-XXXX-XXXX", maxLength: 40 },
    ok: "Join",
    onOk: (code) => invoke("join_group", { code }),
  });
  if (joined) await reloadGroups();
}

let inviteTimer;
async function showInvite() {
  const group = activeGroup();
  if (!group) return;
  const invite = await call("create_invite", { groupId: group.id });
  const countdown = el("p", "countdown");
  const expires = new Date(invite.expires_at).getTime();
  const tick = () => {
    const left = Math.max(0, Math.round((expires - Date.now()) / 1000));
    countdown.textContent = left
      ? `Expires in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}. One person can use it.`
      : "Expired. Create a new code.";
  };
  tick();
  clearInterval(inviteTimer);
  inviteTimer = setInterval(tick, 1000);
  await dialog({
    title: `Invite to ${group.name}`,
    text: "The code carries no keys. Keep Hermes open: your app admits whoever uses it while it's valid. They will only see messages from that point on.",
    code: invite.code,
    body: countdown,
    ok: "Copy",
    onOk: async () => {
      await navigator.clipboard.writeText(invite.code);
      banner("Invite code copied.");
    },
  });
  clearInterval(inviteTimer);
}

async function showMembers() {
  const group = activeGroup();
  if (!group || group.removed) return;
  const list = el("ul", "members");
  const render = async () => {
    const members = await call("members", { groupId: group.id });
    list.replaceChildren(
      ...members.map((m) => {
        const li = el("li", "member");
        const who = el("div", "member-who");
        who.append(el("span", "member-name", (m.name || "Unnamed") + (m.me ? " (you)" : "")), el("span", "fingerprint", m.fingerprint));
        li.append(who, el("span", "tag", ROLE_LABEL[m.role]));
        const act = async (fn) => {
          try {
            await fn();
            await render();
          } catch (e) {
            $("dialog-error").textContent = String(e);
          }
        };
        if (!m.me && group.role === "owner" && m.role !== "owner") {
          const promote = m.role === "admin" ? "member" : "admin";
          const b = el("button", "btn small", m.role === "admin" ? "Make member" : "Make admin");
          b.type = "button";
          b.onclick = () => act(() => invoke("set_role", { groupId: group.id, userId: m.user_id, role: promote }));
          li.append(b);
        }
        const canRemove = !m.me && m.role !== "owner" && (group.role === "owner" || (group.role === "admin" && m.role === "member"));
        if (canRemove) {
          const b = el("button", "btn small danger", "Remove");
          b.type = "button";
          b.onclick = () => act(() => invoke("remove_member", { groupId: group.id, userId: m.user_id }));
          li.append(b);
        }
        return li;
      }),
    );
  };
  await render();
  await dialog({
    title: `${group.name}: members`,
    text: "Removing someone rotates the group keys: they can't read anything sent afterwards.",
    body: list,
    ok: "Done",
    cancel: false,
  });
}

async function leaveGroup() {
  const group = activeGroup();
  if (!group) return;
  const confirmed = await dialog({
    title: group.removed ? `Delete ${group.name}?` : `Leave ${group.name}?`,
    text: group.removed
      ? "This deletes the conversation from this device."
      : "This deletes the group and its history from this device. You'd need a new invite code to come back.",
    ok: group.removed ? "Delete" : "Leave",
    onOk: () => invoke("leave_group", { groupId: group.id }).then(() => true),
  });
  if (!confirmed) return;
  state.messages.delete(group.id);
  closeChat();
  await reloadGroups();
}

// ---------- chat ----------

function showChat(show) {
  $("chat-view").hidden = !show;
  $("chat-placeholder").hidden = show;
  $("app").classList.toggle("in-chat", show);
}

function closeChat() {
  state.active = null;
  renderGroups();
  showChat(false);
}

function renderChatChrome() {
  const g = activeGroup();
  $("chat-title").textContent = g.name;
  $("show-invite").hidden = g.removed || g.role === "member";
  $("show-members").hidden = g.removed;
  $("leave").textContent = g.removed ? "Delete" : "Leave";
  $("removed-banner").hidden = !g.removed;
  $("composer").hidden = g.removed;
}

async function openGroup(id) {
  if (!state.groups.some((g) => g.id === id)) return;
  state.active = id;
  state.unread.delete(id);
  renderGroups();
  renderChatChrome();
  showChat(true);
  state.messages.set(id, await call("messages", { groupId: id }));
  if (state.active === id) renderMessages(true);
  if (!activeGroup().removed) $("input").focus();
}

function mergeMessage(m) {
  const list = state.messages.get(m.group_id);
  if (!list || list.some((x) => x.id === m.id)) return false;
  list.push(m);
  return true;
}

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const dayFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

function renderMessages(scrollToEnd) {
  const box = $("messages");
  const list = state.messages.get(state.active) || [];
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;

  const nodes = [];
  let prev = null;
  for (const m of list) {
    const when = new Date(m.sent_at);
    if (!prev || new Date(prev.sent_at).toDateString() !== when.toDateString()) {
      nodes.push(el("div", "hint day", dayFmt.format(when)));
      prev = null;
    }
    const grouped = prev && prev.sender_credential === m.sender_credential;
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
  box.replaceChildren(...nodes);
  if (scrollToEnd || nearBottom) box.scrollTop = box.scrollHeight;
}

async function send(e) {
  e.preventDefault();
  const input = $("input");
  const text = input.value.trim();
  if (!text || !state.active) return;
  const groupId = state.active;
  // Reuse the id of a failed attempt with the same text: if that attempt
  // actually reached the server, everyone still sees the message once.
  const d = state.draft;
  const id = d && d.groupId === groupId && d.text === text ? d.id : crypto.randomUUID();
  input.value = "";
  autosize();
  try {
    const msg = await call("send_message", { groupId, id, text });
    state.draft = null;
    mergeMessage(msg);
    if (state.active === groupId) renderMessages(true);
  } catch {
    state.draft = { groupId, id, text };
    input.value = text;
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
    case "groups_changed":
      reloadGroups();
      break;
    case "join_failed":
      banner(payload.reason);
      reloadGroups();
      break;
    case "message": {
      const m = payload.message;
      const added = mergeMessage(m);
      if (m.group_id === state.active) {
        if (added) renderMessages(false);
      } else if (!m.mine) {
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
  $("show-invite").onclick = showInvite;
  $("show-members").onclick = showMembers;
  $("leave").onclick = leaveGroup;
  $("back").onclick = closeChat;
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
  try {
    state.profile = await invoke("profile");
  } catch (err) {
    $("status").className = "status offline";
    await dialog({
      title: "Hermes can't open its secure storage",
      text: String(err) + " Hermes keeps its keys in the system keystore and never writes them to disk in clear.",
      cancel: false,
      ok: "OK",
    });
    return;
  }
  renderProfile();
  await reloadGroups();

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
