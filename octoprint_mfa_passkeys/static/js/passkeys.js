
(function () {
  const pluginId = "mfa_passkeys";
  const pluginBase = "/plugin/" + pluginId;

  function api(path) {
    return pluginBase + path;
  }

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  function qs(sel, root) {
    return (root || document).querySelector(sel);
  }

  function qsa(sel, root) {
    return Array.from((root || document).querySelectorAll(sel));
  }

  function text(el, value) {
    if (el) el.textContent = value == null ? "" : String(value);
  }

  function show(el, value) {
    if (!el) return;
    el.style.display = value ? "" : "none";
  }

  function setHtml(el, value) {
    if (el) el.innerHTML = value || "";
  }

  async function jsonRequest(path, options) {
    const response = await fetch(api(path), Object.assign({
      method: "GET",
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    }, options || {}));

    const payload = await response.json().catch(async function () {
      const message = await response.text();
      throw new Error(message || ("HTTP " + response.status));
    });

    if (!response.ok) {
      throw new Error(payload && payload.error ? payload.error : ("HTTP " + response.status));
    }

    return payload;
  }

  function currentContext() {
    return {
      browser_origin: window.location.origin,
      browser_host: window.location.host
    };
  }

  function b64urlToBuffer(base64url) {
    const pad = "=".repeat((4 - (base64url.length % 4)) % 4);
    const base64 = (base64url + pad).replace(/-/g, "+").replace(/_/g, "/");
    const raw = window.atob(base64);
    const output = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) output[i] = raw.charCodeAt(i);
    return output.buffer;
  }

  function bufferToB64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function decodeCreationOptions(options) {
    const copy = JSON.parse(JSON.stringify(options));
    copy.challenge = b64urlToBuffer(copy.challenge);
    copy.user.id = b64urlToBuffer(copy.user.id);
    if (Array.isArray(copy.excludeCredentials)) {
      copy.excludeCredentials = copy.excludeCredentials.map(function (cred) {
        cred.id = b64urlToBuffer(cred.id);
        return cred;
      });
    }
    if (Array.isArray(copy.pubKeyCredParams) && copy.pubKeyCredParams.length === 0) {
      delete copy.pubKeyCredParams;
    }
    return copy;
  }

  function decodeRequestOptions(options) {
    const copy = JSON.parse(JSON.stringify(options));
    copy.challenge = b64urlToBuffer(copy.challenge);
    if (Array.isArray(copy.allowCredentials)) {
      copy.allowCredentials = copy.allowCredentials.map(function (cred) {
        cred.id = b64urlToBuffer(cred.id);
        return cred;
      });
    }
    return copy;
  }

  function serializeCredential(credential) {
    if (!credential) return null;
    const response = credential.response || {};
    const payload = {
      id: credential.id,
      type: credential.type,
      rawId: bufferToB64url(credential.rawId),
      response: {}
    };

    if (response.clientDataJSON) payload.response.clientDataJSON = bufferToB64url(response.clientDataJSON);
    if (response.attestationObject) payload.response.attestationObject = bufferToB64url(response.attestationObject);
    if (response.authenticatorData) payload.response.authenticatorData = bufferToB64url(response.authenticatorData);
    if (response.signature) payload.response.signature = bufferToB64url(response.signature);
    if (response.userHandle) payload.response.userHandle = bufferToB64url(response.userHandle);
    if (typeof response.getTransports === "function") payload.response.transports = response.getTransports();

    return payload;
  }

  function friendlyDate(ts) {
    if (!ts) return "";
    try {
      return new Date(ts * 1000).toLocaleString();
    } catch (e) {
      return "";
    }
  }

  async function loadUserStatus() {
    const root = qs("#passkeys-usersettings");
    if (!root) return;
    const message = qs(".passkeys-usersettings-message", root);
    const warning = qs(".passkeys-usersettings-warning", root);
    const list = qs(".passkeys-credential-list", root);
    const empty = qs(".passkeys-credential-empty", root);

    try {
      const status = await jsonRequest("/user_status?browser_origin=" + encodeURIComponent(location.origin) + "&browser_host=" + encodeURIComponent(location.host));
      text(qs(".passkeys-usersettings-origin", root), status.expected_origin || "");
      text(qs(".passkeys-usersettings-rpid", root), status.rp_id || "");
      text(qs(".passkeys-usersettings-credit", root), status.developer_credit || "");
      text(warning, status.origin_warning || "");
      show(warning, !!status.origin_warning);
      list.innerHTML = "";
      if (status.credentials && status.credentials.length) {
        show(empty, false);
        status.credentials.forEach(function (cred) {
          const li = document.createElement("li");
          li.className = "passkeys-credential-item";
          const meta = [];
          if (cred.device_type) meta.push("Device: " + cred.device_type);
          if (cred.transports && cred.transports.length) meta.push("Transports: " + cred.transports.join(", "));
          if (cred.last_used) meta.push("Last used: " + friendlyDate(cred.last_used));
          li.innerHTML =
            "<div class='passkeys-credential-line'><strong>" + (cred.friendly_name || "Unnamed passkey") + "</strong></div>" +
            "<div class='passkeys-credential-meta'>" + meta.join(" · ") + "</div>";
          const btn = document.createElement("button");
          btn.className = "btn btn-mini";
          btn.textContent = "Remove";
          btn.addEventListener("click", async function () {
            if (!window.confirm("Remove this passkey from your OctoPrint account?")) return;
            try {
              await jsonRequest("/remove_credential", {
                method: "POST",
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                credentials: "same-origin",
                body: JSON.stringify({ credential_id: cred.credential_id })
              });
              await loadUserStatus();
            } catch (err) {
              text(message, err.message || String(err));
            }
          });
          li.appendChild(btn);
          list.appendChild(li);
        });
      } else {
        show(empty, true);
      }
      text(message, "");
    } catch (err) {
      text(message, err.message || String(err));
    }
  }

  async function enrollPasskey() {
    const root = qs("#passkeys-usersettings");
    if (!root) return;
    const message = qs(".passkeys-usersettings-message", root);
    const friendlyName = (qs(".passkeys-friendly-name", root).value || "").trim();
    text(message, "");
    try {
      const begin = await jsonRequest("/begin_enroll", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(Object.assign(currentContext(), { friendly_name: friendlyName }))
      });
      const credential = await navigator.credentials.create({
        publicKey: decodeCreationOptions(begin.options)
      });
      await jsonRequest("/finish_enroll", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(Object.assign(currentContext(), {
          state_id: begin.state_id,
          credential: serializeCredential(credential)
        }))
      });
      text(message, "Passkey saved.");
      await loadUserStatus();
    } catch (err) {
      text(message, err.message || String(err));
    }
  }

  async function loadAdminStatus() {
    const root = qs("#passkeys-settings");
    if (!root) return;
    const message = qs(".passkeys-settings-message", root);
    try {
      const status = await jsonRequest("/admin_status?browser_origin=" + encodeURIComponent(location.origin) + "&browser_host=" + encodeURIComponent(location.host));
      const rpidField = qs(".passkeys-setting-rpid", root);
      const originField = qs(".passkeys-setting-origin", root);
      const certPathField = qs(".passkeys-setting-cert-path", root);
      const residentField = qs(".passkeys-setting-resident", root);
      const forceHttpsField = qs(".passkeys-setting-force-https", root);
      const buttonLabelField = qs(".passkeys-setting-button-label", root);
      if (rpidField) rpidField.value = status.settings.rp_id || status.rp_id || "";
      if (originField) originField.value = status.settings.origin_override || status.expected_origin || "";
      if (certPathField) certPathField.value = status.settings.certificate_source_path || status.detected_certificate_source_path || "";
      if (residentField) residentField.value = status.settings.resident_key_preference || "preferred";
      if (forceHttpsField) forceHttpsField.checked = !!status.settings.force_https;
      if (buttonLabelField) buttonLabelField.value = status.settings.login_button_label || "Sign in with a Passkey";
      text(qs(".passkeys-settings-origin", root), status.expected_origin || "");
      text(qs(".passkeys-settings-rpid", root), status.rp_id || "");
      text(qs(".passkeys-settings-credit", root), status.developer_credit || "");
      text(qs(".passkeys-settings-download-note", root), status.can_download_cert ? "Public certificate is ready to download." : "No exported certificate is stored yet.");
      show(qs(".passkeys-settings-download-link", root), !!status.can_download_cert);
      if (status.can_download_cert) {
        qs(".passkeys-settings-download-link", root).href = status.cert_download_url;
      }
      text(message, "");
    } catch (err) {
      text(message, err.message || String(err));
    }
  }

  async function saveAdminSettings() {
    const root = qs("#passkeys-settings");
    if (!root) return;
    const message = qs(".passkeys-settings-message", root);
    try {
      await jsonRequest("/save_config", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({
          rp_id: (qs(".passkeys-setting-rpid", root) || {}).value || "",
          origin_override: (qs(".passkeys-setting-origin", root) || {}).value || "",
          certificate_source_path: (qs(".passkeys-setting-cert-path", root) || {}).value || "",
          resident_key_preference: (qs(".passkeys-setting-resident", root) || {}).value || "preferred",
          force_https: !!((qs(".passkeys-setting-force-https", root) || {}).checked),
          login_button_label: (qs(".passkeys-setting-button-label", root) || {}).value || "Sign in with a Passkey"
        })
      });
      text(message, "Settings saved.");
      await loadAdminStatus();
    } catch (err) {
      text(message, err.message || String(err));
    }
  }

  async function importCertificate() {
    const root = qs("#passkeys-settings");
    if (!root) return;
    const message = qs(".passkeys-settings-message", root);
    try {
      const result = await jsonRequest("/import_public_cert", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({
          certificate_source_path: (qs(".passkeys-setting-cert-path", root) || {}).value || ""
        })
      });
      text(message, result.message || "Certificate imported.");
      await loadAdminStatus();
    } catch (err) {
      text(message, err.message || String(err));
    }
  }


  function ensurePasskeyLoginButton() {
    const usernameField = qs("#login-user") || qs("input[name='user']") || qs("input[data-test-id='login-username']");
    const passwordField = qs("#login-password") || qs("input[name='pass']") || qs("input[data-test-id='login-password']") || qs("input[type='password']");
    if (!usernameField && !passwordField) return false;

    const host = (usernameField && (usernameField.closest("form") || usernameField.parentElement)) ||
                 (passwordField && (passwordField.closest("form") || passwordField.parentElement));
    if (!host) return false;

    let existing = document.querySelector(".passkeys-login-panel");
    if (existing) return true;

    const panel = document.createElement("div");
    panel.className = "passkeys-login-panel";
    panel.innerHTML =
      "<button type='button' class='btn btn-primary passkeys-login-button'>Sign in with a Passkey</button>" +
      "<div class='passkeys-login-help'>Use an enrolled passkey to sign in directly from this login page. If your passkey is discoverable, you can leave Username blank. Otherwise, enter your OctoPrint username first.</div>" +
      "<div class='passkeys-login-message'></div>";

    const form = usernameField ? (usernameField.form || usernameField.closest("form")) : (passwordField ? passwordField.form || passwordField.closest("form") : null);
    if (form) {
      form.appendChild(panel);
    } else if (passwordField && passwordField.parentElement) {
      passwordField.parentElement.insertAdjacentElement("afterend", panel);
    } else {
      host.appendChild(panel);
    }

    const rememberField = form ? qs("input[name='remember'], input#login-remember", form) : null;
    const msg = qs(".passkeys-login-message", panel);
    const button = qs(".passkeys-login-button", panel);

    button.addEventListener("click", async function () {
      text(msg, "");
      button.disabled = true;
      try {
        await signInWithPasskey(usernameField, rememberField, msg);
      } catch (err) {
        text(msg, err.message || String(err));
      } finally {
        button.disabled = false;
      }
    });

    return true;
  }


  function initStandalonePasskeyPage() {
    const root = qs("#passkeys-standalone-login");
    if (!root) return;
    const usernameField = qs(".passkeys-standalone-username", root);
    const rememberField = qs(".passkeys-standalone-remember", root);
    const messageEl = qs(".passkeys-login-message", root);
    const button = qs(".passkeys-standalone-login-button", root);
    if (!button) return;
    button.addEventListener("click", async function () {
      text(messageEl, "");
      button.disabled = true;
      try {
        await signInWithPasskey(usernameField, rememberField, messageEl);
      } catch (err) {
        text(messageEl, err.message || String(err));
      } finally {
        button.disabled = false;
      }
    });
  }

  async function signInWithPasskey(usernameField, rememberField, messageEl) {
    if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.get) {
      throw new Error("This browser does not support WebAuthn passkeys.");
    }

    const username = usernameField ? (usernameField.value || "").trim() : "";
    const remember = !!(rememberField && rememberField.checked);

    const begin = await jsonRequest("/begin_login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(Object.assign(currentContext(), {
        username: username,
        remember: remember
      }))
    });

    if (!begin.available) {
      throw new Error(username ? "No enrolled passkey was found for that OctoPrint username." : "No discoverable passkey is available for this OctoPrint instance. Enter your username or enroll a passkey first.");
    }

    const assertion = await navigator.credentials.get({
      publicKey: decodeRequestOptions(begin.options)
    });

    const finish = await jsonRequest("/finish_login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(Object.assign(currentContext(), {
        state_id: begin.state_id,
        remember: remember,
        credential: serializeCredential(assertion)
      }))
    });

    if (messageEl) text(messageEl, "");
    window.location.assign(finish.redirect || "/");
  }

  function injectLoginButton() {
    ensurePasskeyLoginButton();
  }

  window.ensurePasskeyLoginButton = ensurePasskeyLoginButton;
  window.OctoPrintMfaPasskeys = window.OctoPrintMfaPasskeys || {};
  window.OctoPrintMfaPasskeys.ensurePasskeyLoginButton = ensurePasskeyLoginButton;

  ready(function () {
    injectLoginButton();
    initStandalonePasskeyPage();

    const userRoot = qs("#passkeys-usersettings");
    if (userRoot) {
      const enrollButton = qs(".passkeys-enroll-button", userRoot);
      if (enrollButton) {
        enrollButton.addEventListener("click", function () {
          enrollPasskey();
        });
      }
      loadUserStatus();
    }

    ensurePasskeyLoginButton();

    const settingsRoot = qs("#passkeys-settings");
    if (settingsRoot) {
      const saveButton = qs(".passkeys-settings-save", settingsRoot);
      const importButton = qs(".passkeys-settings-import-cert", settingsRoot);
      if (saveButton) saveButton.addEventListener("click", saveAdminSettings);
      if (importButton) importButton.addEventListener("click", importCertificate);
      loadAdminStatus();
    }

    setInterval(function () {
      ensurePasskeyLoginButton();
    }, 1000);

    const observer = new MutationObserver(function () {
      ensurePasskeyLoginButton();
    });
    observer.observe(document.documentElement || document.body, { childList: true, subtree: true });

    window.setTimeout(ensurePasskeyLoginButton, 250);
    window.setTimeout(ensurePasskeyLoginButton, 1000);
    window.setTimeout(ensurePasskeyLoginButton, 2500);
  });
})();
