"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const fragment = location.hash.slice(1);
  history.replaceState(null, "", location.pathname);
  // Per-tab recovery retains only this local UI session secret, never login codes.
  if (/^[0-9a-f]{64}$/.test(fragment)) sessionStorage.setItem("maco-account-session", fragment);
  const secret = sessionStorage.getItem("maco-account-session") || "";
  let selection = { revision: 0, selected_alias: null };
  let accounts = [];
  let login = null;
  let loginTimer = null;
  let loginGeneration = 0;
  let busy = false;
  const messages = {
    refused: "操作が拒否されました。ログイン機能とアカウントの設定を確認してください。",
    selection_conflict: "別の画面で選択が変更されました。一覧を更新してください。",
    unsafe_state: "保存した選択を安全に読み込めません。起動設定を確認してください。",
    unsafe_endpoint: "接続先を確認できません。起動設定を確認してください。",
    unavailable: "アカウントサービスに接続できません。",
    timeout: "応答を確認できませんでした。操作は自動で再試行されません。",
    protocol: "アカウントサービスの応答を確認できません。",
    invalid_input: "入力を確認してください。"
  };
  const tell = (text, error = false) => { $("message").textContent = text; $("message").classList.toggle("error", error); };
  async function api(route, body) {
    let response;
    try {
      response = await fetch(`/api/${route}`, { method: "POST", headers: { "Authorization": `Bearer ${secret}`, "Content-Type": "application/json" }, body: JSON.stringify(body), cache: "no-store", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" });
    } catch (_) { throw { code: "unavailable" }; }
    const value = await response.json();
    if (!response.ok) throw { code: value.error || "protocol" };
    return value;
  }
  const report = error => tell(messages[error.code] || "操作を確認できません。状況を確認してから、もう一度操作してください。", true);
  function node(tag, text, className) { const result = document.createElement(tag); if (text !== undefined) result.textContent = text; if (className) result.className = className; return result; }
  function button(text, action, disabled, className) { const result = node("button", text, className); result.type = "button"; result.disabled = !!disabled; result.addEventListener("click", action); return result; }
  function clearDetails() { $("observed").textContent = "まだ取得していません"; $("auth-state").textContent = "「このアカウントの情報を更新」で取得できます。"; $("quota").replaceChildren(); $("models").replaceChildren(); }
  function renderAccounts() {
    $("reload").disabled = busy;
    $("cancel").disabled = busy;
    $("selected-name").textContent = selection.selected_alias || "未選択";
    $("refresh").disabled = busy || !accounts.some(account => account.alias === selection.selected_alias && account.enabled);
    $("accounts").replaceChildren();
    if (!accounts.length) $("accounts").append(node("p", "登録アカウントはありません。"));
    for (const account of accounts) {
      const selected = account.alias === selection.selected_alias;
      const card = node("article", undefined, `card${selected ? " selected" : ""}`);
      const title = node("h3", account.alias);
      if (selected) title.append(node("span", "選択中", "badge"));
      card.append(title, node("p", account.enabled ? "OpenAI · Codex" : "無効になっています", "note"));
      const actions = node("div", undefined, "actions");
      actions.append(button(selected ? "選択中" : "このアカウントを使う", () => select(account.alias), busy || !account.enabled || selected, "primary"));
      actions.append(button("ログイン / 再認証", () => startLogin(account.alias), busy || !account.enabled));
      card.append(actions); $("accounts").append(card);
    }
  }
  async function reload(recover) {
    busy = true; renderAccounts();
    try {
      const data = await api("list", {});
      if (selection.revision !== data.selection.revision) clearDetails();
      accounts = data.inventory.accounts; selection = data.selection; renderAccounts();
      if (recover && selection.selected_alias) await recoverLogin(selection.selected_alias);
    } catch (error) { report(error); }
    finally { busy = false; renderAccounts(); }
  }
  async function select(alias) {
    busy = true; renderAccounts();
    try { const result = await api("select", { alias, expected_revision: selection.revision }); selection = result.selection; clearDetails(); tell(`${alias} を選択しました。`); }
    catch (error) { report(error); }
    finally { busy = false; renderAccounts(); }
  }
  const authLabels = { unknown: "ログイン状態は不明です。", unauthenticated: "ログインしていません。", local_login: "ログイン情報があります。接続の確認はまだできていません。", remote_validated: "取得時点で認証を確認しました。", reauth_required: "再認証が必要です。" };
  const date = value => value === null ? "不明" : new Date(value * 1000).toLocaleString();
  async function refresh() {
    const requested = { ...selection };
    busy = true; renderAccounts();
    try {
      const result = await api("discover", { alias: requested.selected_alias, expected_revision: requested.revision });
      if (selection.revision !== requested.revision) return;
      const observation = result.observation;
      $("observed").textContent = `取得: ${date(observation.observed_at)}`;
      $("auth-state").textContent = authLabels[observation.auth.state];
      $("quota").replaceChildren();
      if (observation.quota.state === "unknown" || !observation.quota.windows.length) $("quota").append(node("p", "利用枠は不明です。残量や次回の補充は確認できていません。", "note"));
      for (const window of observation.quota.windows) {
        const card = node("div", undefined, "quota");
        const duration = window.window_duration_mins === null ? "期間不明" : `${window.window_duration_mins} 分の枠`;
        card.append(node("strong", duration), node("p", `${window.used_percent}% 使用（取得時点）`));
        const bar = node("progress"); bar.max = 100; bar.value = window.used_percent; bar.setAttribute("aria-label", "取得時点の使用率"); card.append(bar);
        card.append(node("p", `リセット予定: ${date(window.resets_at)}`, "note"));
        if (window.resets_at !== null) { const countdown = node("p", "", "note countdown"); countdown.dataset.reset = String(window.resets_at); card.append(countdown); }
        $("quota").append(card);
      }
      $("models").replaceChildren();
      if (observation.models.state === "unknown") $("models").append(node("p", "モデル一覧はまだ確認できていません。", "note"));
      else {
        const table = node("table"); const head = node("thead"); const row = node("tr"); row.append(node("th", "モデル"), node("th", "推論の強さ")); head.append(row); table.append(head); const body = node("tbody");
        for (const model of observation.models.items) { const row = node("tr"); row.append(node("td", model.id), node("td", model.supported_reasoning_efforts.map(effort => effort + (effort === model.default_reasoning_effort ? "（既定）" : "")).join(" · ") || "不明")); body.append(row); }
        table.append(body); $("models").append(table);
      }
      tell(observation.failure ? "一部の情報を確認できませんでした。表示は取得できた内容のみです。" : "選択中のアカウントを確認しました。", !!observation.failure); updateCountdowns();
    } catch (error) { report(error); }
    finally { busy = false; renderAccounts(); }
  }
  const loginLabels = { starting: "認証の準備中です。", pending: "認証ページで操作を完了してください。", confirming: "ログイン完了を確認しています。", ready: "ログインが完了しました。使う場合は、このアカウントを手動で選択してください。", cancelled: "ログイン操作をキャンセルしました。認証情報がすでに保存されている場合があります。", expired: "ログイン操作の待機時間が終了しました。再開にはもう一度ログインを押してください。", failed: "ログインを完了できませんでした。設定を確認してから再度操作してください。", superseded: "新しいログイン操作があります。状況を確認してください。" };
  const active = result => ["starting", "pending", "confirming"].includes(result.status);
  function showLogin(result) {
    clearTimeout(loginTimer); login = result; $("login").hidden = false;
    $("login-title").textContent = `${result.alias} のログイン`;
    $("login-status").textContent = loginLabels[result.status];
    $("device").hidden = result.status !== "pending";
    $("device-code").textContent = result.user_code || "";
    $("cancel").hidden = !active(result);
    $("login-deadline").textContent = active(result) ? `この操作の待機期限: ${date(result.broker_deadline)}（コードの有効期限ではありません）` : "";
    if (active(result)) loginTimer = setTimeout(() => pollLogin(result.alias, result.handle), 1000);
  }
  async function pollLogin(alias, handle) {
    const generation = loginGeneration;
    try { const result = await api("login/status", { alias, handle }); if (generation === loginGeneration && login && login.alias === alias && login.handle === handle) showLogin(result); }
    catch (error) { if (generation !== loginGeneration) return; clearTimeout(loginTimer); $("device").hidden = true; $("device-code").textContent = ""; $("cancel").hidden = true; $("login-status").textContent = "ログイン状況を確認できません。自動で再開しません。"; report(error); }
  }
  async function recoverLogin(alias) {
    clearLoginForCheck(alias);
    try { showLogin(await api("login/status", { alias })); }
    catch (error) { $("login-status").textContent = "進行中のログインを確認できません。ログインボタンから状況を確認してください。"; if (error.code !== "refused") report(error); }
  }
  function clearLoginForCheck(alias) {
    loginGeneration++; clearTimeout(loginTimer); login = null;
    $("login").hidden = false; $("login-title").textContent = `${alias} のログイン`;
    $("login-status").textContent = "ログイン状況を確認しています。";
    $("device").hidden = true; $("device-code").textContent = "";
    $("cancel").hidden = true; $("login-deadline").textContent = "";
  }
  async function startLogin(alias) {
    clearLoginForCheck(alias);
    busy = true; renderAccounts();
    try {
      let previous = null;
      try { previous = await api("login/status", { alias }); } catch (error) { if (error.code !== "refused") throw error; }
      if (previous && active(previous)) { showLogin(previous); return; }
      // Only this explicit click creates a nonce or invokes login/start. No retry.
      const result = await api("login/start", { alias, request_nonce: crypto.randomUUID(), replace_handle: previous ? previous.handle : null });
      showLogin(result); $("login").scrollIntoView({ block: "nearest" });
    } catch (error) { $("login-status").textContent = "ログイン操作の結果を確認できません。自動で再開しません。"; report(error); }
    finally { busy = false; renderAccounts(); }
  }
  async function cancelLogin() {
    if (!login) return;
    const { alias, handle } = login;
    clearLoginForCheck(alias); busy = true; renderAccounts();
    try { showLogin(await api("login/cancel", { alias, handle })); }
    catch (error) { $("login-status").textContent = "キャンセルの結果を確認できません。ログインボタンから状況を確認してください。"; report(error); }
    finally { busy = false; renderAccounts(); }
  }
  function updateCountdowns() {
    for (const element of document.querySelectorAll(".countdown")) {
      const seconds = Math.ceil(Number(element.dataset.reset) - Date.now() / 1000);
      element.textContent = seconds <= 0 ? "予定時刻を過ぎました。補充の確認には情報を更新してください。" : `予定まで ${Math.floor(seconds / 3600)} 時間 ${Math.floor(seconds % 3600 / 60)} 分`;
    }
  }
  $("reload").addEventListener("click", () => reload(true)); $("refresh").addEventListener("click", refresh); $("cancel").addEventListener("click", cancelLogin);
  $("copy").addEventListener("click", async () => { try { await navigator.clipboard.writeText($("device-code").textContent); tell("コードをコピーしました。"); } catch (_) { tell("コードを選択してコピーしてください。"); } });
  setInterval(updateCountdowns, 1000); // Display-only clock; no provider refresh.
  if (secret) reload(true); else tell("起動時に表示されたリンクから、この画面を開いてください。", true);
})();
