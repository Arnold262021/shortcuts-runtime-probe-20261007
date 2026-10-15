const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CODE_LENGTH = 12;
const SESSION_MS = 300_000;
const OPEN_TIMEOUT_MS = 15_000;
const CONNECTION_PROBE_MS = 2_000;
const UUID_HEX = /^[0-9a-f]{32}$/;

const element = (id) => document.getElementById(id);
const ui = Object.freeze({
  form: element("note-pair-form"),
  input: element("note-pair-code"),
  start: element("note-start"),
  stop: element("note-stop"),
  state: element("note-state"),
  timer: element("note-timer"),
});

const session = {
  attempted: false,
  stopped: false,
  stream: null,
  peer: null,
  call: null,
  beganAt: 0,
  ticker: null,
  connectionProbe: null,
  connectionTimeout: null,
};

const labels = Object.freeze({
  waiting: "En espera",
  selecting: "Elige la nota",
  connecting: "Conectando",
  connected: "Conectado",
  stopped: "Detenido",
  elapsed: "Tiempo agotado",
  unconfirmed: "No confirmado",
  rejected: "Origen no aceptado",
});

export function normalizeCode(value) {
  if (typeof value !== "string") return null;
  const normalized = value.replace(/[\s-]/g, "").toUpperCase();
  if (normalized.length !== CODE_LENGTH) return null;
  return [...normalized].every((character) => ALPHABET.includes(character)) ? normalized : null;
}

function setStatus(name) {
  ui.state.textContent = labels[name] || labels.unconfirmed;
}

function renderTimer() {
  const remaining = session.beganAt ? Math.max(0, Math.ceil((SESSION_MS - (performance.now() - session.beganAt)) / 1000)) : Math.ceil(SESSION_MS / 1000);
  ui.timer.textContent = `${String(Math.floor(remaining / 60)).padStart(2, "0")}:${String(remaining % 60).padStart(2, "0")}`;
  if (session.stream && remaining === 0) stop("elapsed");
}

function stopTracks(stream) {
  if (!stream) return;
  try {
    for (const track of stream.getTracks()) {
      try { track.stop(); } catch {}
    }
  } catch {}
}

function stop(reason) {
  if (session.stopped) return;
  session.stopped = true;
  if (session.ticker !== null) clearInterval(session.ticker);
  if (session.connectionProbe !== null) clearTimeout(session.connectionProbe);
  if (session.connectionTimeout !== null) clearTimeout(session.connectionTimeout);
  session.ticker = null;
  session.connectionProbe = null;
  session.connectionTimeout = null;
  stopTracks(session.stream);
  session.stream = null;
  try { if (session.call) session.call.close(); } catch {}
  session.call = null;
  try { if (session.peer) session.peer.destroy(); } catch {}
  session.peer = null;
  ui.stop.disabled = true;
  setStatus(reason);
}

function validAcceptedStream(stream) {
  try {
    if (!stream || stream.getTracks().length !== 1 || stream.getVideoTracks().length !== 1 || stream.getAudioTracks().length !== 0) return false;
    const track = stream.getVideoTracks()[0];
    return track.readyState === "live";
  } catch {
    return false;
  }
}

function senderId() {
  const raw = typeof globalThis.crypto?.randomUUID === "function" ? globalThis.crypto.randomUUID().replaceAll("-", "") : "";
  return UUID_HEX.test(raw) ? `fux-note-sender-v1-${raw}` : null;
}

function waitForOpen(peer) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("PEER_OPEN_TIMEOUT"));
    }, OPEN_TIMEOUT_MS);
    peer.on("open", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve();
    });
    peer.on("error", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(new Error("PEER_OPEN_ERROR"));
    });
  });
}

function bindConnection(call) {
  const check = () => {
    if (session.stopped || session.call !== call) return;
    const connection = call.peerConnection;
    if (!connection || typeof connection.connectionState !== "string" || typeof connection.addEventListener !== "function") {
      stop("unconfirmed");
      return;
    }
    const update = () => {
      if (session.stopped || session.call !== call) return;
      if (connection.connectionState === "connected") {
        if (session.connectionTimeout !== null) clearTimeout(session.connectionTimeout);
        session.connectionTimeout = null;
        setStatus("connected");
      }
      else if (["failed", "disconnected", "closed"].includes(connection.connectionState)) stop("unconfirmed");
    };
    connection.addEventListener("connectionstatechange", update);
    update();
  };
  session.connectionProbe = setTimeout(check, CONNECTION_PROBE_MS);
  call.on("close", () => stop("unconfirmed"));
  call.on("error", () => stop("unconfirmed"));
}

async function start(event) {
  event.preventDefault();
  if (session.attempted) return;
  const code = normalizeCode(ui.input.value);
  if (!code) {
    setStatus("rejected");
    return;
  }
  if (globalThis.isSecureContext !== true || globalThis.location?.protocol !== "https:") {
    setStatus("unconfirmed");
    return;
  }
  session.attempted = true;
  ui.input.value = "";
  ui.input.remove();
  ui.form.hidden = true;
  ui.stop.disabled = false;
  setStatus("selecting");

  let granted;
  try {
    granted = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
    if (session.stopped) {
      stopTracks(granted);
      return;
    }
    if (!validAcceptedStream(granted)) {
      stopTracks(granted);
      stop("rejected");
      return;
    }
    session.stream = granted;
    session.beganAt = performance.now();
    session.ticker = setInterval(renderTimer, 250);
    renderTimer();
    const track = granted.getVideoTracks()[0];
    track.addEventListener("ended", () => stop("stopped"), { once: true });
    track.addEventListener("mute", () => stop("stopped"), { once: true });

    const id = senderId();
    if (!id || typeof globalThis.Peer !== "function") {
      stop("unconfirmed");
      return;
    }
    const peer = new globalThis.Peer(id, {
      debug: 0,
      config: { iceServers: [{ urls: "stun:stun.l.google.com:19302" }] },
    });
    session.peer = peer;
    peer.on("error", () => stop("unconfirmed"));
    peer.on("disconnected", () => stop("unconfirmed"));
    peer.on("close", () => stop("unconfirmed"));
    await waitForOpen(peer);
    if (session.stopped || performance.now() - session.beganAt >= SESSION_MS) {
      if (!session.stopped) stop("elapsed");
      return;
    }
    const call = peer.call(`fux-note-v1-${code}`, granted, { metadata: { scope: "fux-note-v1" } });
    if (!call) {
      stop("unconfirmed");
      return;
    }
    session.call = call;
    setStatus("connecting");
    session.connectionTimeout = setTimeout(() => stop("unconfirmed"), OPEN_TIMEOUT_MS);
    bindConnection(call);
  } catch {
    if (granted && granted !== session.stream) stopTracks(granted);
    stop("unconfirmed");
  }
}

ui.form.addEventListener("submit", start);
ui.stop.addEventListener("click", () => stop("stopped"));
window.addEventListener("pagehide", () => stop("stopped"));
setStatus("waiting");
