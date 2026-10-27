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
  const BROKER_URL = "wss://broker.hivemq.com:8884/mqtt";
  const REQUEST_TOPIC = "demotest/secure/request";
  const RESPONSE_PREFIX = "demotest/secure/response/";
  // Match the AES key and IV+ciphertext base64 framing in the provided demotest.py.
  // It is a public demo key, not suitable for protecting private/production data.
  const SECRET_KEY_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const clientId = (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`).replace(/[^a-zA-Z0-9_-]/g, "");
  const responseTopic = `${RESPONSE_PREFIX}${clientId}`;
  let cryptoKey = null;
  let mqttClient = null;
  let mqttConnected = false;
  let mqttSubscribed = false;
  let authenticated = false;
  let sessionToken = null; // retained for the existing UI handler; MQTT routes per clientId
  let currentPin = "";
  let latestLocalSave = null;
  let localSalt = null;
  let localSaveKey = null;
  let currentAssistantElement = null;
  let currentAssistantText = "";
  let waitingForTurn = false;
  let toastTimer = null;
  let pendingRequest = null;
  let requestCounter = 0;
  let sendChain = Promise.resolve();
  // WebCrypto decrypt is asynchronous. Queue MQTT frames so a fast terminal event
  // can never overtake earlier token frames and reset the visible response.
  let inboundMessageChain = Promise.resolve();
  let lastServerSequence = -1;

  function setPinStatus(message, isError = false) {
    if (!els.pinStatus) return;
    els.pinStatus.textContent = String(message ?? "");
    els.pinStatus.classList.toggle("error", Boolean(isError));
  }
  function setConnection(connected, label = "Disconnected") {
    if (!els.connectionBadge) return;
    els.connectionBadge.textContent = String(label || (connected ? "Connected" : "Disconnected"));
    els.connectionBadge.classList.toggle("offline", !connected);
    els.connectionBadge.setAttribute("aria-label", `Connection status: ${els.connectionBadge.textContent}`);
  }
  function showScreen(target) {
    for (const screen of [els.pinScreen, els.homeScreen, els.creatorScreen, els.chatScreen]) {
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
    toastTimer = setTimeout(() => { els.toast.classList.add("hidden"); toastTimer = null; }, 3600);
  }

  function hexToBytes(hex) {
    if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error("The configured demo AES key is invalid.");
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  }
  function bytesToB64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(binary);
  }
  function b64ToBytes(value) {
    const binary = atob(value);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }
  async function makeCryptoKey() {
    return crypto.subtle.importKey("raw", hexToBytes(SECRET_KEY_HEX), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }
  async function encryptPayload(plainText) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, new TextEncoder().encode(plainText));
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return bytesToB64(combined);
  }
  async function decryptPayload(encoded) {
    const raw = b64ToBytes(encoded);
    if (raw.length < 28) throw new Error("Response payload is too short.");
    const iv = raw.slice(0, 12);
    const ciphertext = raw.slice(12);
    const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ciphertext);
    const outer = JSON.parse(new TextDecoder().decode(clear));
    if (outer && typeof outer.text === "string") {
      try { return JSON.parse(outer.text); }
      catch (_) { return { type: "token", text: outer.text }; }
    }
    return outer;
  }

  function connectMqtt() {
    setConnection(false, "Connecting to HiveMQ");
    setPinStatus("Connecting to the public HiveMQ broker…");
    if (!window.mqtt || typeof window.mqtt.connect !== "function") {
      setConnection(false, "MQTT library unavailable");
      setPinStatus("The MQTT browser library failed to load. Refresh the site or check the network/content blocker.", true);
      return;
    }
    makeCryptoKey().then((key) => { cryptoKey = key; }).then(() => {
      mqttClient = window.mqtt.connect(BROKER_URL, {
        clientId: `isekai_${clientId.slice(0, 22)}`,
        clean: true,
        connectTimeout: 15000,
        reconnectPeriod: 4000,
        keepalive: 30,
        protocolVersion: 4
      });
      mqttClient.on("connect", () => {
        mqttConnected = true;
        setConnection(false, "Subscribing…");
        mqttClient.subscribe(responseTopic, { qos: 1 }, (error) => {
          if (error) {
            mqttSubscribed = false;
            setConnection(false, "Subscribe failed");
            setPinStatus(`HiveMQ connected, but response subscription failed: ${error.message || error}`, true);
            return;
          }
          mqttSubscribed = true;
          setConnection(true, "HiveMQ connected");
          setPinStatus("Connected. Enter access code 7782 to begin.");
        });
      });
      mqttClient.on("reconnect", () => {
        mqttConnected = false;
        mqttSubscribed = false;
        setConnection(false, "Reconnecting to HiveMQ");
      });
      mqttClient.on("offline", () => {
        mqttConnected = false;
        mqttSubscribed = false;
        setConnection(false, "HiveMQ offline");
      });
      mqttClient.on("error", (error) => {
        console.error("HiveMQ MQTT error", error);
        setConnection(false, "HiveMQ connection error");
        setPinStatus(`HiveMQ connection error: ${error?.message || error}`, true);
      });
      mqttClient.on("message", (topic, payload) => {
        if (topic !== responseTopic) return;
        const encoded = new TextDecoder().decode(payload);
        // Preserve broker delivery order across async AES-GCM decryptions.
        inboundMessageChain = inboundMessageChain
          .then(() => receiveMqttResponse(encoded))
          .catch((error) => console.error("Ordered MQTT message handler failed", error));
      });
    }).catch((error) => {
      setConnection(false, "Encryption unavailable");
      setPinStatus(error.message || "Could not initialize message encryption.", true);
    });
  }

  async function receiveMqttResponse(encoded) {
    try {
      const message = await decryptPayload(encoded);
      if (!message || typeof message !== "object") throw new Error("Decrypted response is not an event object.");

      // Public MQTT topics can receive delayed or duplicate replies. Every app
      // request carries a unique request_id; never let an older turn mutate the
      // current UI or make the browser wait for a response that belongs elsewhere.
      const activeRequest = pendingRequest;
      if (!activeRequest) return;
      if (!message.request_id || message.request_id !== activeRequest.requestId) {
        console.debug("Ignoring uncorrelated/stale MQTT event", message.type, message.request_id || "(no request_id)");
        return;
      }
      if (Number.isInteger(message.stream_seq)) {
        if (message.stream_seq <= lastServerSequence) return; // QoS 1 may redeliver.
        if (lastServerSequence >= 0 && message.stream_seq !== lastServerSequence + 1) {
          console.warn(`MQTT response sequence gap for ${activeRequest.requestId}: expected ${lastServerSequence + 1}, got ${message.stream_seq}`);
        }
        lastServerSequence = message.stream_seq;
      }
      console.debug("Isekai stream event", message.type, "seq", message.stream_seq,
        message.type === "token" ? `chars=${String(message.text || "").length}` : "");
      await handleBody(message);
      if (pendingRequest === activeRequest && isTerminalEvent(activeRequest.type, message.type)) {
        const pending = activeRequest;
        pendingRequest = null;
        clearTimeout(pending.timeout);
        pending.resolve(message);
      }
    } catch (error) {
      console.error("Could not decode HiveMQ response", error);
      const info = "Could not decrypt a HiveMQ response. The browser and Python worker must use the same key from demotest.py.";
      if (!authenticated) setPinStatus(info, true);
      else showChatNotice(info);
      if (pendingRequest) {
        const pending = pendingRequest;
        pendingRequest = null;
        clearTimeout(pending.timeout);
        pending.reject(new Error(info));
      }
    }
  }

  function isTerminalEvent(requestType, eventType) {
    if (["auth_error", "server_error"].includes(eventType)) return true;
    if (requestType === "auth") return eventType === "connection_status";
    if (["create_story", "chat_turn"].includes(requestType)) return eventType === "turn_complete" || eventType === "story_error";
    if (requestType === "import_save") return eventType === "import_ok";
    if (requestType === "load_save") return eventType === "save_status";
    if (requestType === "ping") return eventType === "pong";
    return eventType === "turn_complete" || eventType === "story_error" || eventType === "import_ok" || eventType === "save_status";
  }

  let currentSave = null;
  let latestSave = null;
  function secureSend(body) {
    const operation = sendChain.then(() => performSecureSend(body));
    sendChain = operation.catch(() => {});
    return operation;
  }

  function waitForMqtt(timeoutMs = 20000) {
    if (mqttConnected && mqttSubscribed && cryptoKey) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const started = Date.now();
      const timer = setInterval(() => {
        if (mqttConnected && mqttSubscribed && cryptoKey) {
          clearInterval(timer); resolve();
        } else if (Date.now() - started >= timeoutMs) {
          clearInterval(timer); reject(new Error("HiveMQ is not connected. Check your internet connection and refresh the page."));
        }
      }, 120);
    });
  }

  async function performSecureSend(body) {
    await waitForMqtt();
    if (pendingRequest) throw new Error("Another request is still running. Wait for it to finish.");
    return new Promise(async (resolve, reject) => {
      lastServerSequence = -1;
      const requestId = `${clientId}_${Date.now().toString(36)}_${(++requestCounter).toString(36)}`;
      const pending = { type: body.type, requestId, resolve, reject, timeout: null };
      pending.timeout = setTimeout(() => {
        if (pendingRequest !== pending) return;
        pendingRequest = null;
        reject(new Error("No response arrived from the Python worker. Make sure isekai_server.py and the DeepSeek bridge are running."));
      }, 12 * 60 * 1000);
      pendingRequest = pending;
      try {
        // Exact demotest.py envelope fields: clientId, prompt, image.
        const requestData = JSON.stringify({ clientId, requestId, prompt: JSON.stringify(body), image: "" });
        const encrypted = await encryptPayload(requestData);
        if (!mqttConnected || !mqttSubscribed) throw new Error("HiveMQ disconnected before the request could be sent.");
        mqttClient.publish(REQUEST_TOPIC, encrypted, { qos: 1, retain: false }, (error) => {
          if (error && pendingRequest === pending) {
            pendingRequest = null;
            clearTimeout(pending.timeout);
            reject(new Error(`Could not publish to HiveMQ: ${error.message || error}`));
          }
        });
      } catch (error) {
        if (pendingRequest === pending) pendingRequest = null;
        clearTimeout(pending.timeout);
        reject(error);
      }
    });
  }
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
      case "turn_complete": {
        els.creatorSubmitButton.disabled = false;
        if (message.save) currentSave = message.save;
        // The saved answer is canonical. Reconcile it into the live chat before
        // completing the turn, even if a broker/browser dropped all token events.
        const savedMessages = Array.isArray(currentSave?.messages) ? currentSave.messages : [];
        const finalAssistant = [...savedMessages].reverse().find((item) => item?.role === "assistant");
        const canonicalText = (typeof finalAssistant?.content === "string" && finalAssistant.content.trim())
          ? finalAssistant.content
          : (typeof message.text === "string" ? message.text : "");
        if (canonicalText.trim()) {
          if (!currentAssistantElement) currentAssistantElement = addMessage("assistant", canonicalText);
          else renderMessageBody(currentAssistantElement, canonicalText);
          currentAssistantText = canonicalText;
          currentAssistantElement.dataset.messageId = `assistant-${Date.now()}`;
          scrollToBottom();
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
      }
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
        setWaiting(false);
        els.creatorSubmitButton.disabled = false;
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
    if (!mqttConnected || !mqttSubscribed || !cryptoKey) {
      setPinStatus("HiveMQ is still connecting. Wait for the connected status, then try again.", true);
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

  connectMqtt();
})();
