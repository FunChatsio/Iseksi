(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const els = {
    pinScreen: $("pinScreen"), pinForm: $("pinForm"), pinInput: $("pinInput"), pinStatus: $("pinStatus"),
    mqttHost: $("mqttHost"), mqttWsPort: $("mqttWsPort"), mqttTopicRoot: $("mqttTopicRoot"),
    mqttAppSecret: $("mqttAppSecret"),
    mqttConnectButton: $("mqttConnectButton"),
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
  const MQTT_CONFIG_KEY = "isekai_hivemq_mqtt_config_v1";
  const MQTT_DEFAULT_TOPIC_ROOT = "isekai/chat/v1/4da4543ebc851d5c65d113c8";

  let mqttConfig = null;
  let mqttClient = null;
  let mqttTopics = null;
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
  let lastServerPackets = [];
  let serverMessageChain = Promise.resolve();

  // Centralized status helper used by the PIN screen and MQTT connection flow.
  // This was missing in the GitHub Pages build, causing connect() to throw
  // before the MQTT session could be established.
  function setPinStatus(message, isError = false) {
    if (!els.pinStatus) return;
    els.pinStatus.textContent = String(message ?? "");
    els.pinStatus.classList.toggle("error", Boolean(isError));
  }

  function normaliseTopicRoot(value) {
    const root = String(value || "").trim().replace(/^\/+|\/+$/g, "");
    if (!root || /[+#\s]/.test(root) || root.split("/").some((p) => !p || p === "." || p === "..")) {
      throw new Error("Topic prefix must be a normal MQTT topic path, without wildcards, spaces, or empty parts.");
    }
    return root;
  }

  function readMqttConfigFromForm() {
    const host = els.mqttHost.value.trim().replace(/^wss?:\/\//i, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
    const port = Number(els.mqttWsPort.value || 8884);
    const appSecret = els.mqttAppSecret.value;
    const topicRoot = normaliseTopicRoot(els.mqttTopicRoot.value || MQTT_DEFAULT_TOPIC_ROOT);
    if (!host || /[^a-zA-Z0-9.-]/.test(host) || host.startsWith(".") || host.endsWith(".")) {
      throw new Error("Enter a valid broker hostname, without https://.");
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Enter a valid secure WebSocket port (normally 8884).");
    if (appSecret.length < 32) throw new Error("The private app encryption secret must be at least 32 characters long.");
    return { host, port, appSecret, topicRoot };
  }

  function loadMqttConfig() {
    try {
      const saved = JSON.parse(localStorage.getItem(MQTT_CONFIG_KEY) || "null");
      if (!saved || typeof saved !== "object") return;
      els.mqttHost.value = saved.host || "";
      els.mqttWsPort.value = String(saved.port || 8884);
      // Older builds persisted passwords/secrets. Purge those values and only
      // retain non-sensitive public-broker settings in localStorage.
      els.mqttTopicRoot.value = saved.topicRoot || MQTT_DEFAULT_TOPIC_ROOT;
      if (saved.appSecret || saved.password || saved.username) {
        localStorage.setItem(MQTT_CONFIG_KEY, JSON.stringify({ host: saved.host || "broker.hivemq.com", port: saved.port || 8884, topicRoot: saved.topicRoot || MQTT_DEFAULT_TOPIC_ROOT }));
      }
    } catch (_) { /* Ignore malformed locally stored settings. */ }
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

  async function establishCrypto(serverHello) {
    if (serverHello.type !== "hello") throw new Error("Unexpected HiveMQ server handshake.");
    const serverPublicBytes = b64ToBytes(serverHello.public_key);
    const serverPublic = await crypto.subtle.importKey(
      "spki", serverPublicBytes, { name: "ECDH", namedCurve: "P-256" }, false, []
    );
    const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: serverPublic }, ephemeralKeyPair.privateKey, 256);
    const secretBytes = new TextEncoder().encode(mqttConfig.appSecret);
    const ikm = new Uint8Array(sharedBits.byteLength + secretBytes.byteLength);
    ikm.set(new Uint8Array(sharedBits), 0);
    ikm.set(secretBytes, sharedBits.byteLength);
    const hkdfKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
    cryptoKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: b64ToBytes(serverHello.salt), info: new TextEncoder().encode("isekai-chat-v1") },
      hkdfKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
    ikm.fill(0);
    new Uint8Array(sharedBits).fill(0);
    setPinStatus("HiveMQ connected. Messages are end-to-end encrypted. Enter your code.");
  }

  let ephemeralKeyPair = null;

  function mqttPublish(topic, payload) {
    return new Promise((resolve, reject) => {
      if (!mqttClient || !mqttClient.connected) return reject(new Error("HiveMQ MQTT is disconnected."));
      mqttClient.publish(topic, payload, { qos: 1, retain: false }, (error) => error ? reject(error) : resolve());
    });
  }

  function mqttSubscribe(topic) {
    return new Promise((resolve, reject) => {
      if (!mqttClient || !mqttClient.connected) return reject(new Error("HiveMQ MQTT is disconnected."));
      mqttClient.subscribe(topic, { qos: 1 }, (error) => error ? reject(error) : resolve());
    });
  }

  async function beginMqttSession() {
    const sessionId = crypto.randomUUID().replace(/-/g, "");
    mqttTopics = {
      client: `${mqttConfig.topicRoot}/${sessionId}/client`,
      server: `${mqttConfig.topicRoot}/${sessionId}/server`
    };
    cryptoKey = null;
    clientOutSeq = 0;
    serverInSeq = 0;
    lastServerPackets = [];
    serverMessageChain = Promise.resolve();
    ephemeralKeyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const publicKey = await crypto.subtle.exportKey("spki", ephemeralKeyPair.publicKey);
    await mqttSubscribe(mqttTopics.server);
    await mqttPublish(mqttTopics.client, JSON.stringify({ type: "client_hello", public_key: bytesToB64(new Uint8Array(publicKey)) }));
    setPinStatus("HiveMQ connected. Establishing private encrypted session…");
  }

  function connect() {
    let config;
    try {
      config = readMqttConfigFromForm();
    } catch (error) {
      setPinStatus(error.message, true);
      return;
    }
    if (!window.mqtt || typeof window.mqtt.connect !== "function") {
      setPinStatus("MQTT.js could not load. Refresh the page or check whether unpkg.com is blocked.", true);
      return;
    }
    mqttConfig = config;
    try {
      localStorage.setItem(MQTT_CONFIG_KEY, JSON.stringify({ host: config.host, port: config.port, topicRoot: config.topicRoot }));
    } catch (_) { /* Connection works even if browser storage is disabled. */ }
    if (mqttClient) {
      const previous = mqttClient;
      mqttClient = null;
      try { previous.end(true); } catch (_) { /* Ignore previous connection cleanup. */ }
    }
    authenticated = false;
    cryptoKey = null;
    mqttTopics = null;
    setPinStatus(`Connecting to public HiveMQ at ${config.host}:${config.port}…`);
    setConnection(false, "Connecting");
    try {
      mqttClient = window.mqtt.connect(`wss://${config.host}:${config.port}/mqtt`, {
        clientId: `isekai-web-${crypto.randomUUID().replace(/-/g, "").slice(0, 18)}`,
        protocolVersion: 4,
        clean: true,
        keepalive: 25,
        connectTimeout: 15000,
        reconnectPeriod: 0,
        resubscribe: false
      });
      mqttClient.on("connect", () => beginMqttSession().catch((error) => setPinStatus(`MQTT setup failed: ${error.message}`, true)));
      mqttClient.on("message", (topic, payload) => {
        if (!mqttTopics || topic !== mqttTopics.server) return;
        const raw = payload.toString();
        // WebCrypto decrypt is asynchronous. Chain packet processing so streamed
        // tokens cannot finish decrypting out of order and trip the sequence guard.
        serverMessageChain = serverMessageChain.then(async () => {
          const fingerprint = bytesToB64(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw))));
          if (lastServerPackets.includes(fingerprint)) return; // QoS 1 may redeliver the identical packet.
          lastServerPackets.push(fingerprint);
          if (lastServerPackets.length > 256) lastServerPackets.shift();
          const packet = JSON.parse(raw);
          if (packet.type === "hello") {
            await establishCrypto(packet);
            return;
          }
          if (packet.type === "secure") {
            await handleSecurePacket(packet);
            return;
          }
          throw new Error("Unencrypted application message rejected.");
        }).catch((error) => {
          console.error("MQTT message processing failed", error);
          toast(`Secure message error: ${error.message}`);
        });
      });
      mqttClient.on("error", (error) => {
        console.error("HiveMQ MQTT error", error);
        setPinStatus(`HiveMQ connection error: ${error.message || "check hostname, port, and credentials"}`, true);
      });
      mqttClient.on("close", () => {
        authenticated = false;
        cryptoKey = null;
        setConnection(false, "Disconnected");
        if (!els.chatScreen.classList.contains("hidden")) toast("HiveMQ disconnected. Your last completed turn remains autosaved.");
      });
      mqttClient.on("offline", () => setConnection(false, "Offline"));
    } catch (error) {
      setPinStatus(`Cannot connect to HiveMQ: ${error.message}`, true);
    }
  }

  async function secureSend(body) {
    if (!mqttClient || !mqttClient.connected || !cryptoKey || !mqttTopics) throw new Error("The encrypted HiveMQ session is not ready.");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = new TextEncoder().encode(JSON.stringify({ seq: clientOutSeq, body }));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, payload);
    await mqttPublish(mqttTopics.client, JSON.stringify({ type: "secure", iv: bytesToB64(iv), ciphertext: bytesToB64(new Uint8Array(ciphertext)) }));
    clientOutSeq += 1;
  }

  async function handleSecurePacket(packet) {
    if (!cryptoKey) throw new Error("Encryption key is unavailable.");
    const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(packet.iv) }, cryptoKey, b64ToBytes(packet.ciphertext));
    const decoded = JSON.parse(new TextDecoder().decode(clear));
    if (decoded.seq !== serverInSeq) throw new Error("Message sequence mismatch; refusing a replay or reordered frame.");
    serverInSeq += 1;
    await handleBody(decoded.body || {});
  }

  let currentSave = null;
  let latestSave = null;

  async function handleBody(message) {
    switch (message.type) {
      case "auth_ok": {
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
    if (!mqttClient || !mqttClient.connected || !cryptoKey) {
      setPinStatus("The encrypted HiveMQ session is not ready. Check the broker settings and Python server.", true);
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

  els.mqttConnectButton.addEventListener("click", () => connect());

  // Load saved HiveMQ settings locally; credentials are never included in the repository code.
  loadMqttConfig();
  if (els.mqttHost.value.trim() && els.mqttAppSecret.value.length >= 32) {
    connect();
  } else {
    setPinStatus("Enter the same private app secret configured in your Python server, then connect to public HiveMQ.");
  }
})();
