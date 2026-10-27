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
  const WS_URL = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`;
  let ws = null;
  let cryptoKey = null;
  let clientOutSeq = 0;
  let serverInSeq = 0;
  let authenticated = false;
  let currentPin = "";
  let currentSave = null;
  let latestSave = null;
  let latestLocalSave = null;
  let localSalt = null;
  let localSaveKey = null;
  let currentAssistantElement = null;
  let currentAssistantText = "";
  let waitingForTurn = false;
  let toastTimer = null;

  function showScreen(screen) {
    [els.pinScreen, els.homeScreen, els.creatorScreen, els.chatScreen].forEach((el) => el.classList.add("hidden"));
    screen.classList.remove("hidden");
  }

  function setPinStatus(text, error = false) {
    els.pinStatus.textContent = text;
    els.pinStatus.classList.toggle("error", error);
  }

  function toast(message) {
    els.toast.textContent = message;
    els.toast.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => els.toast.classList.add("hidden"), 3200);
  }

  function setConnection(connected, label = "Connected") {
    els.connectionBadge.textContent = label;
    els.connectionBadge.classList.toggle("offline", !connected);
    if (!connected) {
      setPinStatus("Can't reach the local story server. Start isekai_server.py and refresh this page.", true);
    }
  }

  function bytesToB64(bytes) {
    let binary = "";
    const step = 0x8000;
    for (let i = 0; i < bytes.length; i += step) {
      binary += String.fromCharCode(...bytes.subarray(i, i + step));
    }
    return btoa(binary);
  }

  function b64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  async function establishCrypto(clientHello) {
    if (clientHello.type !== "hello") throw new Error("Unexpected server handshake.");
    const serverPublicBytes = b64ToBytes(clientHello.public_key);
    const serverPublic = await crypto.subtle.importKey(
      "spki", serverPublicBytes, { name: "ECDH", namedCurve: "P-256" }, false, []
    );
    const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: serverPublic }, ephemeralKeyPair.privateKey, 256);
    const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
    cryptoKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: b64ToBytes(clientHello.salt), info: new TextEncoder().encode("isekai-chat-v1") },
      hkdfKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
    new Uint8Array(sharedBits).fill(0);
    setPinStatus("Secure connection ready. Enter your code.");
  }

  let ephemeralKeyPair = null;

  function connect() {
    setPinStatus("Connecting to your local world…");
    try {
      ws = new WebSocket(WS_URL);
      ws.addEventListener("open", async () => {
        try {
          ephemeralKeyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
          const publicKey = await crypto.subtle.exportKey("spki", ephemeralKeyPair.publicKey);
          ws.send(JSON.stringify({ type: "client_hello", public_key: bytesToB64(new Uint8Array(publicKey)) }));
          setPinStatus("Secure connection ready. Enter your code.");
        } catch (error) {
          setPinStatus(`Browser encryption could not start: ${error.message}`, true);
        }
      });
      ws.addEventListener("message", async (event) => {
        try {
          const packet = JSON.parse(event.data);
          if (packet.type === "hello") {
            await establishCrypto(packet);
            return;
          }
          if (packet.type === "secure") {
            await handleSecurePacket(packet);
            return;
          }
          throw new Error("Unencrypted application message rejected.");
        } catch (error) {
          console.error("Message processing failed", error);
          toast(`Secure message error: ${error.message}`);
        }
      });
      ws.addEventListener("close", () => {
        authenticated = false;
        setConnection(false, "Disconnected");
        if (!els.chatScreen.classList.contains("hidden")) toast("Connection closed. Your last completed turn remains autosaved.");
      });
      ws.addEventListener("error", () => setPinStatus("Connection failed. Check that the Python server is running.", true));
    } catch (error) {
      setPinStatus(`Cannot open WebSocket: ${error.message}`, true);
    }
  }

  async function secureSend(body) {
    if (!ws || ws.readyState !== WebSocket.OPEN || !cryptoKey) throw new Error("Secure connection is not ready.");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = new TextEncoder().encode(JSON.stringify({ seq: clientOutSeq++, body }));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, payload);
    ws.send(JSON.stringify({ type: "secure", iv: bytesToB64(iv), ciphertext: bytesToB64(new Uint8Array(ciphertext)) }));
  }

  async function handleSecurePacket(packet) {
    if (!cryptoKey) throw new Error("Encryption key is unavailable.");
    const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(packet.iv) }, cryptoKey, b64ToBytes(packet.ciphertext));
    const decoded = JSON.parse(new TextDecoder().decode(clear));
    if (decoded.seq !== serverInSeq) throw new Error("Message sequence mismatch; refusing a replay or reordered frame.");
    serverInSeq += 1;
    await handleBody(decoded.body || {});
  }

  async function handleBody(message) {
    switch (message.type) {
      case "auth_ok": {
        authenticated = true;
        currentPin = els.pinInput.value.trim();
        els.pinInput.value = "";
        setConnection(true, "Local & encrypted");
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
    if (!ws || ws.readyState !== WebSocket.OPEN || !cryptoKey) {
      setPinStatus("The secure connection is not ready yet. Start the Python server and refresh.", true);
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

  // Start the encrypted WebSocket handshake immediately, while the PIN screen remains visible.
  connect();
})();
