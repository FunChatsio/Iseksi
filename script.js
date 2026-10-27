(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const els = {
    pinScreen: $("pinScreen"), pinForm: $("pinForm"), pinInput: $("pinInput"), pinStatus: $("pinStatus"),
    homeScreen: $("homeScreen"), creatorScreen: $("creatorScreen"), chatScreen: $("chatScreen"),
    connectionBadge: $("connectionBadge"), homeStatus: $("homeStatus"), newStoryButton: $("newStoryButton"),
    continueButton: $("continueButton"), importButton: $("importButton"), importFile: $("importFile"),
    backHomeButton: $("backHomeButton"), characterForm: $("characterForm"), characterName: $("characterName"),
    appearance: $("appearance"), ageInput: $("ageInput"), ageHint: $("ageHint"), charismaInput: $("charismaInput"),
    charismaValue: $("charismaValue"), privateHistory: $("privateHistory"), creatorError: $("creatorError"),
    worldTitle: $("worldTitle"), worldDate: $("worldDate"), messageList: $("messageList"), chatForm: $("chatForm"),
    chatInput: $("chatInput"), sendButton: $("sendButton"), typingStatus: $("typingStatus"), exportButton: $("exportButton"),
    homeFromChatButton: $("homeFromChatButton"), creatorSubmitButton: $("characterForm").querySelector('button[type="submit"]'), chatNotice: $("chatNotice"), saveIndicator: $("saveIndicator"), toast: $("toast")
  };

  const STORAGE_KEY = "isekai_autosave_enc_v1";
  const LAUNCH_CONFIG_KEY = "isekai_direct_lan_launch_v1";

  let apiBase = null;
  let appSecret = "";
  let sessionToken = null;
  let clientId = crypto.randomUUID().replace(/-/g, "");
  let cryptoKey = null;
  let clientOutSeq = 0;
  let serverInSeq = 0;
  let authenticated = false;
  let currentPin = "";
  let latestLocalSave = null;
  let localSalt = null;
  let localSaveKey = null;
  let currentAssistantElement = null;
  let currentAssistantText = "";
  let waitingForTurn = false;
  let toastTimer = null;

  // Status helper for the direct LAN HTTP connection and PIN screen.
  function setPinStatus(message, isError = false) {
    if (!els.pinStatus) return;
    els.pinStatus.textContent = String(message ?? "");
    els.pinStatus.classList.toggle("error", Boolean(isError));
  }

  // Shared UI helpers. Keep these defined in one place so every connection
  // and navigation path can safely update the UI.
  function setConnection(connected, label = "Disconnected") {
    if (!els.connectionBadge) return;
    els.connectionBadge.textContent = String(label || (connected ? "Connected" : "Disconnected"));
    els.connectionBadge.classList.toggle("offline", !connected);
    els.connectionBadge.setAttribute("aria-label", `Connection status: ${els.connectionBadge.textContent}`);
  }

  function showScreen(target) {
    const screens = [els.pinScreen, els.homeScreen, els.creatorScreen, els.chatScreen];
    for (const screen of screens) {
      if (!screen) continue;
      screen.classList.toggle("hidden", screen !== target);
      screen.setAttribute("aria-hidden", screen === target ? "false" : "true");
    }
  }

  function toast(message) {
    if (!els.toast) return;
    els.toast.textContent = String(message ?? "");
    els.toast.classList.remove("hidden");
    if (toastTimer !== null) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      els.toast.classList.add("hidden");
      toastTimer = null;
    }, 3600);
  }

  function readLaunchConfig() {
    // Python prints a ready-to-open GitHub Pages URL with the laptop address
    // in the query and a one-time random transport secret in the URL fragment.
    // Fragments are not sent to GitHub's web server.
    try {
      const query = new URLSearchParams(window.location.search);
      const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ""));
      const server = query.get("server");
      const secret = fragment.get("secret");
      if (server && secret && secret.length >= 32) {
        const parsed = new URL(server);
        if (parsed.protocol !== "http:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
          throw new Error("The launch link contains an invalid laptop address.");
        }
        const config = { base: parsed.origin, secret };
        sessionStorage.setItem(LAUNCH_CONFIG_KEY, JSON.stringify(config));
        // Hide one-time connection details from the visible address bar.
        history.replaceState(null, "", window.location.pathname);
        return config;
      }
      const saved = JSON.parse(sessionStorage.getItem(LAUNCH_CONFIG_KEY) || "null");
      if (saved && typeof saved.base === "string" && typeof saved.secret === "string" && saved.secret.length >= 32) {
        return saved;
      }
    } catch (error) {
      console.warn("Could not read Isekai launch link", error);
      setPinStatus(error.message || "Invalid launch link. Open the latest link printed by isekai_server.py.", true);
    }
    return null;
  }

  function bytesToB64(bytes) {
    let binary = "";
    const step = 0x8000;
    for (let i = 0; i < bytes.length; i += step) binary += String.fromCharCode(...bytes.subarray(i, i + step));
    return btoa(binary);
  }

  function b64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  async function deriveHttpCrypto(secret) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
    const material = await crypto.subtle.importKey("raw", digest, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode("isekai-http-v1"), info: new TextEncoder().encode("isekai-chat-v1") },
      material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }

  async function localFetch(url, options = {}) {
    // Supported by recent Chromium browsers. This lets an HTTPS GitHub Pages page
    // request a private HTTP LAN IP after the user grants Local Network Access.
    return fetch(url, { ...options, targetAddressSpace: "local", mode: "cors", cache: "no-store", credentials: "omit" });
  }

  async function connect(config = readLaunchConfig()) {
    if (!config) {
      setConnection(false, "Waiting for laptop");
      setPinStatus("Start isekai_server.py on your laptop, then open the launch link it prints.");
      return;
    }

    apiBase = config.base;
    appSecret = config.secret;
    authenticated = false;
    sessionToken = null;
    cryptoKey = null;
    clientOutSeq = 0;
    serverInSeq = 0;
    clientId = crypto.randomUUID().replace(/-/g, "");
    setConnection(false, "Connecting to laptop");
    setPinStatus(`Connecting directly to ${apiBase}…`);

    try {
      cryptoKey = await deriveHttpCrypto(appSecret);
      const response = await localFetch(`${apiBase}/api/health`, { method: "GET" });
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(`Laptop server returned HTTP ${response.status}${detail ? `: ${detail.slice(0, 180)}` : ""}`);
      }
      const health = await response.json();
      setConnection(true, "Laptop connected");
      const bridgeStatus = health.bridge_reachable ? "DeepSeek bridge is reachable." : (health.bridge_message || "The Python server is reachable, but the local DeepSeek bridge is offline.");
      setPinStatus(`Laptop connected. ${bridgeStatus} Enter access code 7782.`);
    } catch (error) {
      cryptoKey = null;
      setConnection(false, "Laptop offline");
      let detail = error && error.message ? error.message : String(error);
      if (error instanceof TypeError) {
        detail = "Browser could not reach the laptop. Allow Local Network Access for this site, check the laptop IP and Windows Firewall, and make sure both devices are on the same Wi-Fi.";
      }
      setPinStatus(detail, true);
    }
  }

  let secureSendChain = Promise.resolve();
  function secureSend(body) {
    const operation = secureSendChain.then(() => performSecureSend(body));
    secureSendChain = operation.catch(() => {});
    return operation;
  }

  async function performSecureSend(body) {
    if (!apiBase || !cryptoKey) throw new Error("Connect to your laptop first.");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = new TextEncoder().encode(JSON.stringify({ seq: clientOutSeq, body }));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, payload);
    const envelope = { type: "secure", iv: bytesToB64(iv), ciphertext: bytesToB64(new Uint8Array(ciphertext)) };
    clientOutSeq += 1;
    const headers = { "Content-Type": "application/json", "X-Isekai-Client": clientId };
    if (sessionToken) headers["X-Isekai-Session"] = sessionToken;
    const response = await localFetch(`${apiBase}/api/action`, { method: "POST", headers, body: JSON.stringify(envelope) });
    if (!response.ok) {
      const detail = await response.text();
      let reason = detail;
      try { reason = JSON.parse(detail).error || detail; } catch (_) { /* Plain server diagnostic. */ }
      throw new Error(`Laptop API returned HTTP ${response.status}: ${String(reason).slice(0, 350)}`);
    }
    if (!response.body) throw new Error("The browser did not provide an HTTP response stream.");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    const processLine = async (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      await handleSecurePacket(JSON.parse(trimmed));
    };
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";
      for (const line of lines) await processLine(line);
    }
    buffer += decoder.decode();
    if (buffer.trim()) await processLine(buffer);
  }

  async function handleSecurePacket(packet) {
    if (!cryptoKey) throw new Error("Encryption key is unavailable.");
    const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(packet.iv) }, cryptoKey, b64ToBytes(packet.ciphertext));
    const decoded = JSON.parse(new TextDecoder().decode(clear));
    if (decoded.seq !== serverInSeq) throw new Error("Message sequence mismatch. Refresh the site and reconnect.");
    serverInSeq += 1;
    await handleBody(decoded.body || {});
  }

  let currentSave = null;
  let latestSave = null;

  async function handleBody(message) {
    switch (message.type) {
      case "auth_ok": {
        if (message.token) sessionToken = String(message.token);
        authenticated = true;
        currentPin = els.pinInput.value.trim();
        els.pinInput.value = "";
        setConnection(true, "Secure & encrypted");
        showScreen(els.homeScreen);
        els.homeStatus.textContent = "";
        try {
          latestLocalSave = await readLocalSave(currentPin);
          if (latestLocalSave && (!latestSave || (latestLocalSave.updated_at || "") > (latestSave.updated_at || ""))) {
            latestSave = latestLocalSave;
          }
        } catch (error) {
          console.warn("Local autosave could not be read", error);
        }
        updateContinueButton();
        break;
      }
      case "auth_error":
        setPinStatus(message.message || "Incorrect code.", true);
        break;
      case "latest_save":
        if (message.save) {
          latestSave = message.save;
          if (!latestLocalSave || (latestSave.updated_at || "") >= (latestLocalSave.updated_at || "")) {
            try { await writeLocalSave(latestSave); } catch (_) { /* Server copy still exists. */ }
          }
          updateContinueButton();
        }
        break;
      case "connection_status":
        setConnection(Boolean(message.connected), message.label || (message.connected ? "Bridge ready" : "Bridge offline"));
        if (!message.connected) showChatNotice(message.message || "The local DeepSeek bridge is not responding.");
        break;
      case "import_ok":
        currentSave = message.save;
        latestSave = message.save;
        await writeLocalSave(currentSave).catch(() => {});
        enterChat(currentSave);
        toast("Story imported.");
        updateContinueButton();
        break;
      case "story_begin":
        currentSave = message.save || currentSave;
        currentAssistantElement = null;
        currentAssistantText = "";
        els.messageList.innerHTML = "";
        showScreen(els.chatScreen);
        updateWorldHeader();
        setWaiting(true);
        break;
      case "turn_begin":
        currentSave = message.save || currentSave;
        currentAssistantElement = null;
        currentAssistantText = "";
        setWaiting(true);
        break;
      case "memory_work":
        setWaiting(true);
        { const label = els.typingStatus.querySelector("span:last-child"); if (label) label.textContent = message.message || "Recording what happened…"; }
        els.typingStatus.classList.remove("hidden");
        break;
      case "token":
        appendAssistantToken(String(message.text || ""));
        break;
      case "replace":
        currentAssistantText = String(message.text || "");
        ensureAssistantElement();
        renderMessageBody(currentAssistantElement, currentAssistantText);
        scrollToBottom();
        break;
      case "turn_complete":
        els.creatorSubmitButton.disabled = false;
        if (message.save) currentSave = message.save;
        if (currentAssistantElement && currentAssistantText.trim()) {
          currentAssistantElement.dataset.messageId = `assistant-${Date.now()}`;
        }
        setWaiting(false);
        updateWorldHeader();
        if (currentSave) {
          latestSave = currentSave;
          try {
            await writeLocalSave(currentSave);
            els.saveIndicator.textContent = "Autosaved";
          } catch (error) {
            els.saveIndicator.textContent = "Server saved";
            console.warn("Encrypted browser autosave failed", error);
          }
          updateContinueButton();
        }
        currentAssistantElement = null;
        currentAssistantText = "";
        els.chatInput.focus();
        break;
      case "story_error":
        els.creatorSubmitButton.disabled = false;
        setWaiting(false);
        showChatNotice(message.message || "The story request failed.");
        if (currentAssistantText.trim()) toast("The connection ended mid-response. The partial text is still visible; try continuing when ready.");
        currentAssistantElement = null;
        currentAssistantText = "";
        break;
      case "memory_notice":
        showChatNotice(message.message || "The story continued, but a memory update failed. The chat was still saved.");
        break;
      case "save_status":
        if (message.save) currentSave = message.save;
        break;
      case "server_error":
        toast(message.message || "Server error.");
        break;
      case "pong":
        break;
      default:
        console.debug("Unknown server event", message.type);
    }
  }

  function updateContinueButton() {
    const save = latestSave || latestLocalSave;
    els.continueButton.disabled = !save || !Array.isArray(save.messages);
    if (save && save.player) {
      els.continueButton.textContent = `Continue as ${save.player.name || "your character"}`;
    } else {
      els.continueButton.textContent = "Continue your story";
    }
  }

  function updateOriginUi() {
    const origin = document.querySelector('input[name="origin"]:checked')?.value || "peasant";
    document.querySelectorAll("[data-origin-option]").forEach((el) => {
      el.classList.toggle("selected", el.dataset.originOption === origin);
    });
    const isPossession = origin !== "appear";
    els.ageInput.min = isPossession ? "5" : "5";
    els.ageInput.max = isPossession ? "17" : "100";
    if (isPossession && Number(els.ageInput.value) > 17) els.ageInput.value = "17";
    if (!isPossession && Number(els.ageInput.value) < 18) {
      // Do not force an adult; direct arrival can be any age.
    }
    els.ageHint.textContent = isPossession ? "A child’s body (5–17)" : "Any age (5–100)";
  }

  function validateSave(save) {
    if (!save || typeof save !== "object" || !save.player || !Array.isArray(save.messages) || !save.world) {
      throw new Error("This file does not look like a valid Isekai save.");
    }
    if (save.version !== 1) throw new Error("Unsupported save version.");
    if (!save.world_id) throw new Error("Save is missing its world ID.");
    if (save.messages.length > 100000) throw new Error("Save has too many messages.");
    return save;
  }

  function enterChat(save) {
    currentSave = structuredClone(save);
    showScreen(els.chatScreen);
    els.messageList.innerHTML = "";
    for (const message of currentSave.messages || []) {
      if (message.role === "assistant" || message.role === "user") addMessage(message.role, String(message.content || ""));
    }
    updateWorldHeader();
    setWaiting(false);
    scrollToBottom();
    els.chatInput.focus();
  }

  function updateWorldHeader() {
    if (!currentSave) return;
    els.worldTitle.textContent = currentSave.world?.name || currentSave.player?.name || "Your Story";
    els.worldDate.textContent = currentSave.world?.date_label || "Year 1 · Spring · Day 1";
  }

  function addMessage(role, text) {
    const entry = document.createElement("article");
    entry.className = `story-message ${role === "user" ? "user" : "assistant"}`;
    const body = document.createElement("div");
    body.className = "message-body";
    renderMessageBody(body, text);
    entry.appendChild(body);
    els.messageList.appendChild(entry);
    return entry;
  }

  function ensureAssistantElement() {
    if (!currentAssistantElement) {
      currentAssistantElement = addMessage("assistant", "");
      currentAssistantText = "";
    }
    return currentAssistantElement;
  }

  function appendAssistantToken(text) {
    if (!text) return;
    currentAssistantText += text;
    const entry = ensureAssistantElement();
    renderMessageBody(entry, currentAssistantText);
    scrollToBottom();
  }

  function renderMessageBody(element, raw) {
    const text = String(raw || "").replace(/\r\n/g, "\n");
    // Escape all source text first; only our own limited formatting tags survive.
    let safe = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    safe = safe.replace(/\*\*(.+?)\*\*/gs, "<strong>$1</strong>");
    safe = safe.replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, "$1<em>$2</em>");
    const paragraphs = safe.split(/\n{2,}/).map((paragraph) => `<p>${paragraph.replace(/\n/g, "<br>") || "&nbsp;"}</p>`);
    element.innerHTML = paragraphs.join("");
  }

  function scrollToBottom() {
    requestAnimationFrame(() => { els.messageList.scrollTop = els.messageList.scrollHeight; });
  }

  function setWaiting(waiting) {
    waitingForTurn = waiting;
    const typingLabel = els.typingStatus.querySelector("span:last-child");
    if (typingLabel && !waiting) typingLabel.textContent = "Writing the next moment…";
    els.typingStatus.classList.toggle("hidden", !waiting);
    els.chatInput.disabled = waiting;
    els.sendButton.disabled = waiting;
    els.saveIndicator.textContent = waiting ? "Saving…" : "Autosaved";
  }

  function showChatNotice(text) {
    els.chatNotice.textContent = text;
    els.chatNotice.classList.remove("hidden");
  }

  function hideChatNotice() {
    els.chatNotice.textContent = "";
    els.chatNotice.classList.add("hidden");
  }

  async function deriveLocalKey(pin, salt) {
    const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
      material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }

  async function readLocalSave(pin) {
    const serialized = localStorage.getItem(STORAGE_KEY);
    if (!serialized) return null;
    const wrapper = JSON.parse(serialized);
    localSalt = b64ToBytes(wrapper.salt);
    localSaveKey = await deriveLocalKey(pin, localSalt);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(wrapper.iv) }, localSaveKey, b64ToBytes(wrapper.ciphertext));
    const save = validateSave(JSON.parse(new TextDecoder().decode(plain)));
    return save;
  }

  async function writeLocalSave(save) {
    if (!currentPin || !save) return;
    if (!localSalt) localSalt = crypto.getRandomValues(new Uint8Array(16));
    if (!localSaveKey) localSaveKey = await deriveLocalKey(currentPin, localSalt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = new TextEncoder().encode(JSON.stringify(save));
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, localSaveKey, plain);
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      version: 1,
      salt: bytesToB64(localSalt),
      iv: bytesToB64(iv),
      ciphertext: bytesToB64(new Uint8Array(cipher))
    }));
  }

  function exportSave() {
    if (!currentSave) return;
    const blob = new Blob([JSON.stringify(currentSave, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    const name = (currentSave.player?.name || "isekai").normalize("NFKD").replace(/[^a-z0-9-_]+/gi, "-").replace(/^-|-$/g, "").toLowerCase() || "isekai";
    link.download = `${name}-save.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1200);
    toast("Save exported as JSON. The exported file is not encrypted; keep it somewhere private.");
  }

  async function importSaveFile(file) {
    if (!file) return;
    try {
      const text = await file.text();
      const imported = validateSave(JSON.parse(text));
      await secureSend({ type: "import_save", save: imported });
      els.homeStatus.textContent = "Importing story…";
    } catch (error) {
      els.homeStatus.textContent = error.message || "Could not import this save.";
      els.homeStatus.classList.add("error");
    } finally {
      els.importFile.value = "";
    }
  }

  els.pinForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!apiBase || !cryptoKey) {
      setPinStatus("Open the launch link printed by isekai_server.py first.", true);
      return;
    }
    setPinStatus("Checking access code…");
    try { await secureSend({ type: "auth", pin: els.pinInput.value.trim() }); }
    catch (error) { setPinStatus(error.message, true); }
  });

  els.newStoryButton.addEventListener("click", () => {
    els.characterForm.reset();
    els.charismaValue.textContent = els.charismaInput.value;
    els.creatorError.textContent = "";
    updateOriginUi();
    showScreen(els.creatorScreen);
  });

  els.backHomeButton.addEventListener("click", () => showScreen(els.homeScreen));
  document.querySelectorAll('input[name="origin"]').forEach((input) => input.addEventListener("change", updateOriginUi));
  els.charismaInput.addEventListener("input", () => { els.charismaValue.textContent = els.charismaInput.value; });

  els.characterForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!authenticated) return;
    const origin = document.querySelector('input[name="origin"]:checked')?.value || "peasant";
    const age = Number(els.ageInput.value);
    if (!els.characterName.value.trim() || !els.appearance.value.trim()) {
      els.creatorError.textContent = "Enter a name and describe your appearance.";
      return;
    }
    if (!Number.isFinite(age) || age < 5 || age > (origin === "appear" ? 100 : 17)) {
      els.creatorError.textContent = origin === "appear" ? "Choose an age from 5 to 100." : "A possessed host body must be a child aged 5–17.";
      return;
    }
    els.creatorError.textContent = "";
    els.creatorSubmitButton.disabled = true;
    hideChatNotice();
    const character = {
      name: els.characterName.value.trim(),
      age_years: age,
      appearance: els.appearance.value.trim(),
      charisma: Number(els.charismaInput.value),
      origin,
      private_history: els.privateHistory.value.trim()
    };
    try {
      els.creatorError.textContent = "Creating your world…";
      await secureSend({ type: "create_story", character });
      els.creatorError.textContent = "";
    } catch (error) {
      els.creatorSubmitButton.disabled = false;
      els.creatorError.textContent = error.message || "Could not start the story.";
    }
  });

  els.continueButton.addEventListener("click", async () => {
    const save = latestSave || latestLocalSave;
    if (!save) return;
    try {
      const valid = validateSave(save);
      currentSave = structuredClone(valid);
      await secureSend({ type: "load_save", world_id: currentSave.world_id });
      enterChat(currentSave);
    } catch (error) {
      toast(error.message || "Could not continue this story.");
    }
  });

  els.importButton.addEventListener("click", () => els.importFile.click());
  els.importFile.addEventListener("change", () => importSaveFile(els.importFile.files?.[0]));
  els.exportButton.addEventListener("click", exportSave);
  els.homeFromChatButton.addEventListener("click", () => {
    showScreen(els.homeScreen);
    latestSave = currentSave || latestSave;
    updateContinueButton();
  });

  els.chatForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!authenticated || waitingForTurn || !currentSave) return;
    const text = els.chatInput.value.trim();
    if (!text) return;
    els.chatInput.value = "";
    resizeComposer();
    hideChatNotice();
    currentSave.messages = currentSave.messages || [];
    currentSave.messages.push({ role: "user", content: text, at: new Date().toISOString() });
    addMessage("user", text);
    scrollToBottom();
    setWaiting(true);
    try {
      await secureSend({ type: "chat_turn", text, save: currentSave });
    } catch (error) {
      setWaiting(false);
      showChatNotice(`Could not send your message: ${error.message}`);
    }
  });

  function resizeComposer() {
    els.chatInput.style.height = "auto";
    els.chatInput.style.height = `${Math.min(els.chatInput.scrollHeight, 190)}px`;
  }
  els.chatInput.addEventListener("input", resizeComposer);
  els.chatInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      els.chatForm.requestSubmit();
    }
  });

  // Connection settings arrive automatically in the one-time URL generated by Python.
  // On subsequent reloads, reuse this tab's session settings without another form.
  const launchConfig = readLaunchConfig();
  if (launchConfig) {
    connect(launchConfig);
  } else {
    setConnection(false, "Waiting for laptop");
    setPinStatus("Start isekai_server.py on your laptop, then open the launch link it prints.");
  }
})();
