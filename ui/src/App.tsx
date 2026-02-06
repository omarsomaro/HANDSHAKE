import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import QRCode from "qrcode";
import { useSSE } from "./hooks/useSSE";
import { useLogs } from "./hooks/useLogs";
import { TopBar } from "./components/TopBar";
import { WizardSteps } from "./components/WizardSteps";
import { PhaseBar, PhaseState } from "./components/PhaseBar";
import { ConsolePanel } from "./components/ConsolePanel";

const DEFAULT_API_BIND = "127.0.0.1:8731";

const ROLE_OPTIONS = ["auto", "host", "client"] as const;
const WAN_MODES = ["auto", "direct", "tor"] as const;
const TOR_ROLES = ["client", "host"] as const;
const GUARANTEED_EGRESS = ["public", "tor"] as const;
const PLUGGABLE_TRANSPORTS = ["none", "https", "ftp", "dns", "websocket", "quic"] as const;
const STEALTH_MODES = ["active", "passive", "mdns"] as const;
const FLOW_MODES = ["classic", "offer", "hybrid", "target", "phrase", "guaranteed"] as const;

type FlowMode = (typeof FLOW_MODES)[number];

const FLOW_LABELS: Record<FlowMode, string> = {
  classic: "Classic cascade",
  offer: "Offer QR",
  hybrid: "Hybrid QR (resume)",
  target: "Target direct",
  phrase: "Easy Tor (Phrase)",
  guaranteed: "Guaranteed relay"
};

const FLOW_DESC: Record<FlowMode, string> = {
  classic: "LAN -> WAN -> Assist -> Tor fallback with full automation.",
  offer: "QR offer handshake for quick pairing without typing addresses.",
  hybrid: "QR with resume token + deterministic fallback (best UX for re-join).",
  target: "Direct connect to an IP:port or .onion target you already know.",
  phrase: "Tor-friendly invite flow with a private passphrase.",
  guaranteed: "Always-on relay with optional Tor egress."
};

const FLOW_STEPS: Record<FlowMode, string[]> = {
  classic: ["Start daemon", "Set passphrase", "Pick WAN + Tor role", "Connect cascade"],
  offer: ["Start daemon", "Set passphrase", "Generate offer QR", "Client connects with offer"],
  hybrid: [
    "Start daemon",
    "Set passphrase",
    "Generate Hybrid QR",
    "Client connects with QR (resume + fallback)"
  ],
  target: ["Start daemon", "Set passphrase", "Enter target", "Connect direct"],
  phrase: ["Start daemon", "Host opens phrase", "Share invite", "Client joins"],
  guaranteed: ["Start daemon", "Enter passphrase", "Pick egress", "Connect relay"]
};

type DaemonStatus = {
  running: boolean;
  pid?: number | null;
  last_error?: string | null;
  last_exit_code?: number | null;
};

interface StartResult {
  pid: number;
  api_url: string;
  token: string;
}

interface SetPassResponse {
  status: string;
  port: number;
  tag16: number;
  tag8?: number;
}

interface StatusResponse {
  status: string;
  port?: number | null;
  mode: string;
  peer?: string | null;
  resume_status?: string | null;
}

interface OfferResponse {
  offer: string;
  ver: number;
  expires_at_ms: number;
  endpoints: string[];
}

interface HybridQrResponse {
  qr: string;
  offer: string;
  ver: number;
  expires_at_ms: number;
  resume_expires_at_ms: number;
  endpoints: string[];
  relay_hints: string[];
}

interface PluggableCheckResponse {
  pluggable_transport: {
    enabled: boolean;
    status: string;
    checklist: {
      real_tls: string;
      websocket: string;
      http2: string;
      quic: string;
    };
  };
}

interface DebugMetricsResponse {
  connection: {
    transport_mode: string;
    nat_type?: string | null;
    packet_loss_rate: number;
    avg_encrypt_us: number;
    avg_decrypt_us: number;
    connection_errors: number;
  };
  throughput_mbps: number;
  health_score: number;
  status: string;
}

export default function App() {
  const [apiBind, setApiBind] = useState(DEFAULT_API_BIND);
  const [unsafeExpose, setUnsafeExpose] = useState(false);
  const [daemonStatus, setDaemonStatus] = useState<DaemonStatus>({ running: false });
  const [token, setToken] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [localRole, setLocalRole] = useState<(typeof ROLE_OPTIONS)[number]>("auto");
  const [wanMode, setWanMode] = useState<(typeof WAN_MODES)[number]>("auto");
  const [torRole, setTorRole] = useState<(typeof TOR_ROLES)[number]>("client");
  const [connectStatus, setConnectStatus] = useState<StatusResponse | null>(null);
  const [setPassResult, setSetPassResult] = useState<SetPassResponse | null>(null);
  const [offerResult, setOfferResult] = useState<OfferResponse | null>(null);
  const [offerQr, setOfferQr] = useState<string | null>(null);
  const [offerTtl, setOfferTtl] = useState<string>("");
  const [offerRoleHint, setOfferRoleHint] = useState<"host" | "client">("host");
  const [offerLocalRole, setOfferLocalRole] = useState<"host" | "client">("client");
  const [hybridQrResult, setHybridQrResult] = useState<HybridQrResponse | null>(null);
  const [hybridQrImage, setHybridQrImage] = useState<string | null>(null);
  const [hybridQrTtl, setHybridQrTtl] = useState<string>("");
  const [hybridResumeTtl, setHybridResumeTtl] = useState<string>("");
  const [hybridRoleHint, setHybridRoleHint] = useState<"host" | "client">("host");
  const [hybridLocalRole, setHybridLocalRole] = useState<"host" | "client">("client");
  const [hybridIncludeTor, setHybridIncludeTor] = useState<boolean>(false);
  const [hybridRelayHints, setHybridRelayHints] = useState<string>("");
  const [hybridQrInput, setHybridQrInput] = useState<string>("");
  const [phraseInvite, setPhraseInvite] = useState<string>("");
  const [phraseQr, setPhraseQr] = useState<string | null>(null);
  const [phraseStatus, setPhraseStatus] = useState<string>("closed");
  const [joinInvite, setJoinInvite] = useState<string>("");
  const [phrasePassphrase, setPhrasePassphrase] = useState<string>("");
  const [classicOffer, setClassicOffer] = useState<string>("");
  const [classicTarget, setClassicTarget] = useState<string>("");
  const [targetIsOnion, setTargetIsOnion] = useState<boolean>(false);
  const [targetOnion, setTargetOnion] = useState<string>("");
  const [includeTorOffer, setIncludeTorOffer] = useState<boolean>(false);
  const [flowMode, setFlowMode] = useState<FlowMode>("classic");
  const [screen, setScreen] = useState<"home" | "mode">("home");
  const [guaranteedPassphrase, setGuaranteedPassphrase] = useState<string>("");
  const [guaranteedEgress, setGuaranteedEgress] =
    useState<(typeof GUARANTEED_EGRESS)[number]>("public");
  const [guaranteedRelayUrl, setGuaranteedRelayUrl] = useState<string>("");
  const [pluggableTransport, setPluggableTransport] =
    useState<(typeof PLUGGABLE_TRANSPORTS)[number]>("none");
  const [realTlsDomain, setRealTlsDomain] = useState<string>("");
  const [stealthMode, setStealthMode] =
    useState<(typeof STEALTH_MODES)[number]>("active");
  const [assistRelays, setAssistRelays] = useState<string>("");
  const [torSocksAddr, setTorSocksAddr] = useState<string>("");
  const [torOnionAddr, setTorOnionAddr] = useState<string>("");
  const { filtered, filter, setFilter, logLine, clear } = useLogs();
  const [warning, setWarning] = useState<string | null>(null);
  const [sseEnabled, setSseEnabled] = useState(false);
  const [connectAttempted, setConnectAttempted] = useState(false);
  const [pluggableCheck, setPluggableCheck] = useState<PluggableCheckResponse | null>(null);
  const [metrics, setMetrics] = useState<DebugMetricsResponse | null>(null);

  const statusTimer = useRef<number | null>(null);
  const lastDaemonError = useRef<string | null>(null);

  const apiUrl = useMemo(() => `http://${apiBind}`, [apiBind]);
  const authHeader = useMemo(
    () => (token ? { Authorization: `Bearer ${token}` } : {}),
    [token]
  );

  const formatTtl = useCallback((expiresAtMs?: number | null) => {
    if (!expiresAtMs) return "-";
    const delta = Math.max(0, expiresAtMs - Date.now());
    const s = Math.floor(delta / 1000);
    const m = Math.floor(s / 60);
    const h = Math.floor(m / 60);
    if (h > 0) return `${h}h ${m % 60}m`;
    if (m > 0) return `${m}m ${s % 60}s`;
    return `${s}s`;
  }, []);

  const isSymmetricNat = useMemo(() => {
    const nat = metrics?.connection?.nat_type?.toLowerCase() ?? "";
    return nat.includes("symmetric");
  }, [metrics]);

  const modeBadge = useMemo(() => {
    const mode = connectStatus?.mode ?? "unknown";
    if (mode === "lan" || mode === "wan" || mode === "stun") return { label: mode, tone: "ok" };
    if (mode === "wan_tcp") return { label: "wan_tcp (udp blocked)", tone: "warn" };
    if (mode === "wan_tor") return { label: "wan_tor (relay)", tone: "warn" };
    if (mode === "quic" || mode === "webrtc") return { label: mode, tone: "info" };
    return { label: mode, tone: "muted" };
  }, [connectStatus]);

  const healthBadge = useMemo(() => {
    if (!metrics) return { label: "unknown", tone: "muted" };
    if (metrics.health_score >= 80) return { label: "healthy", tone: "ok" };
    if (metrics.health_score >= 50) return { label: "degraded", tone: "warn" };
    return { label: "poor", tone: "danger" };
  }, [metrics]);

  const fetchWithAuth = useCallback(
    async (path: string, options?: RequestInit) => {
      const activeToken = token;
      if (!activeToken) throw new Error("token not loaded");
      const headers = new Headers(options?.headers || {});
      if (activeToken) {
        headers.set("Authorization", `Bearer ${activeToken}`);
      }
      headers.set("Content-Type", "application/json");
      const res = await fetch(`${apiUrl}${path}`, { ...options, headers });
      if (!res.ok) throw new Error(`API error ${res.status}`);
      return res;
    },
    [apiUrl, token]
  );

  const refreshStatus = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetchWithAuth("/v1/status");
      const data = await res.json();
      setConnectStatus(data);
    } catch (err) {
      logLine("STATUS", (err as Error).message);
    }
  }, [fetchWithAuth, logLine, token]);

  const startStatusPoll = useCallback(() => {
    if (statusTimer.current) clearInterval(statusTimer.current);
    statusTimer.current = window.setInterval(refreshStatus, 3000);
  }, [refreshStatus]);

  const stopStatusPoll = useCallback(() => {
    if (statusTimer.current) {
      clearInterval(statusTimer.current);
      statusTimer.current = null;
    }
  }, []);

  const { state: sseState } = useSSE(`${apiUrl}/v1/recv`, {
    enabled: sseEnabled && !!token,
    headers: authHeader,
    onEvent: (evt) => {
      if (evt.data && evt.data !== "ok") {
        logLine("SSE", String(evt.data));
      }
    },
    onError: (err) => {
      logLine("SSE", String(err));
    }
  });

  const handleStartDaemon = useCallback(async () => {
    const isUnsafeBind = apiBind.startsWith("0.0.0.0");
    if (isUnsafeBind && !unsafeExpose) {
      setWarning("Unsafe bind requires --unsafe-expose-api");
      return;
    }

    const cleanedPluggable =
      pluggableTransport === "none" ? undefined : pluggableTransport;
    const cleanedRealTlsDomain = realTlsDomain.trim() || undefined;
    const cleanedStealthMode = stealthMode.trim() || undefined;
    const cleanedAssistRelays = assistRelays.trim() || undefined;
    const cleanedTorSocks = torSocksAddr.trim() || undefined;
    const cleanedTorOnion = torOnionAddr.trim() || undefined;

    try {
      const result = await invoke<StartResult>("start_daemon", {
        apiBind,
        unsafeExposeApi: unsafeExpose,
        pluggableTransport: cleanedPluggable,
        realTlsDomain: cleanedRealTlsDomain,
        stealthMode: cleanedStealthMode,
        assistRelays: cleanedAssistRelays,
        torSocksAddr: cleanedTorSocks,
        torOnionAddr: cleanedTorOnion
      });

      setDaemonStatus({ running: true, pid: result.pid });
      setToken(result.token);
      setWarning(null);
      logLine("DAEMON", `started pid=${result.pid}`);
    } catch (err) {
      const msg = (err as Error).message || String(err);
      setWarning(msg);
      logLine("DAEMON", msg);
      setDaemonStatus({ running: false });
    }
  }, [
    apiBind,
    unsafeExpose,
    pluggableTransport,
    realTlsDomain,
    stealthMode,
    assistRelays,
    torSocksAddr,
    torOnionAddr,
    logLine
  ]);

  const handleFetchDaemonLogs = useCallback(async () => {
    try {
      const logs = (await invoke<string[]>("daemon_logs")) || [];
      if (logs.length === 0) {
        logLine("DAEMON", "no daemon logs yet");
      }
      logs.forEach((line) => logLine("DAEMON", line));
    } catch (err) {
      logLine("DAEMON", `log fetch failed: ${(err as Error).message}`);
    }
  }, [logLine]);

  const handleRefreshPluggable = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/v1/pluggable/check");
      const data = (await res.json()) as PluggableCheckResponse;
      setPluggableCheck(data);
    } catch (err) {
      logLine("PLUGGABLE", (err as Error).message);
    }
  }, [fetchWithAuth, logLine]);

  const handleRefreshMetrics = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/v1/metrics");
      const data = (await res.json()) as DebugMetricsResponse;
      setMetrics(data);
    } catch (err) {
      logLine("METRICS", (err as Error).message);
    }
  }, [fetchWithAuth, logLine]);

  const handleStopDaemon = useCallback(async () => {
    await invoke("stop_daemon");
    setDaemonStatus({ running: false });
    setToken(null);
    stopStatusPoll();
    setSseEnabled(false);
    logLine("DAEMON", "stopped");
  }, [logLine, stopStatusPoll]);

  // Token is passed in-RAM by the launcher; no token file on disk.

  const handleSetPassphrase = useCallback(async () => {
    if (!passphrase) return;
    try {
      const res = await fetchWithAuth("/v1/set_passphrase", {
        method: "POST",
        body: JSON.stringify({ passphrase })
      });
      const data = (await res.json()) as SetPassResponse;
      setSetPassResult(data);
      logLine("PASS", `port=${data.port} tag16=${data.tag16}`);
    } catch (err) {
      logLine("PASS", (err as Error).message);
    }
  }, [fetchWithAuth, passphrase, logLine]);

  const localRolePayload =
    localRole === "auto" ? undefined : localRole;

  const handleConnectCascade = useCallback(async () => {
    if (!passphrase.trim()) return;
    try {
      const res = await fetchWithAuth("/v1/connect", {
        method: "POST",
        body: JSON.stringify({
          product_mode: "classic",
          passphrase,
          wan_mode: wanMode,
          tor_role: torRole,
          local_role: localRolePayload,
          target_onion: targetOnion.trim() || undefined
        })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      logLine("CONNECT", `${data.status} mode=${data.mode}`);
    } catch (err) {
      logLine("CONNECT", (err as Error).message);
    }
  }, [
    fetchWithAuth,
    passphrase,
    wanMode,
    torRole,
    localRolePayload,
    targetOnion,
    logLine
  ]);

  const handleConnectOffer = useCallback(async () => {
    const offerTrim = classicOffer.trim();
    if (!offerTrim) return;
    try {
      const res = await fetchWithAuth("/v1/connect", {
        method: "POST",
        body: JSON.stringify({
          offer: offerTrim,
          local_role: offerLocalRole
        })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      logLine("CONNECT", `${data.status} mode=${data.mode}`);
    } catch (err) {
      logLine("CONNECT", (err as Error).message);
    }
  }, [fetchWithAuth, classicOffer, offerLocalRole, logLine]);

  const handleConnectTarget = useCallback(async () => {
    const targetTrim = classicTarget.trim();
    if (!passphrase.trim() || !targetTrim) return;
    const onion = targetIsOnion ? targetTrim : undefined;
    try {
      const res = await fetchWithAuth("/v1/connect", {
        method: "POST",
        body: JSON.stringify({
          product_mode: "classic",
          passphrase,
          target: targetTrim,
          wan_mode: targetIsOnion ? "tor" : wanMode,
          tor_role: targetIsOnion ? "client" : torRole,
          local_role: localRolePayload,
          target_onion: onion
        })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      logLine("CONNECT", `${data.status} mode=${data.mode}`);
    } catch (err) {
      logLine("CONNECT", (err as Error).message);
    }
  }, [
    fetchWithAuth,
    passphrase,
    classicTarget,
    targetIsOnion,
    wanMode,
    torRole,
    localRolePayload,
    logLine
  ]);

  const handleConnectGuaranteed = useCallback(async () => {
    if (!guaranteedPassphrase.trim()) return;
    try {
      const res = await fetchWithAuth("/v1/connect", {
        method: "POST",
        body: JSON.stringify({
          product_mode: "guaranteed",
          passphrase: guaranteedPassphrase,
          guaranteed_egress: guaranteedEgress,
          guaranteed_relay_url: guaranteedRelayUrl || undefined,
          local_role: localRolePayload
        })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      logLine("GUARANTEED", `${data.status} mode=${data.mode}`);
    } catch (err) {
      logLine("GUARANTEED", (err as Error).message);
    }
  }, [
    fetchWithAuth,
    guaranteedPassphrase,
    guaranteedEgress,
    guaranteedRelayUrl,
    localRolePayload,
    logLine
  ]);

  const refreshPhraseStatus = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/v1/phrase/status");
      const data = (await res.json()) as { status: string };
      setPhraseStatus(data.status);
    } catch (err) {
      logLine("PHRASE", (err as Error).message);
    }
  }, [fetchWithAuth, logLine]);

  const handlePhraseOpen = useCallback(async () => {
    if (!phrasePassphrase.trim()) return;
    try {
      const res = await fetchWithAuth("/v1/phrase/open", {
        method: "POST",
        body: JSON.stringify({ passphrase: phrasePassphrase })
      });
      const data = (await res.json()) as { invite: string };
      setPhraseInvite(data.invite);
      setPhraseQr(await QRCode.toDataURL(data.invite, { width: 280, margin: 1 }));
      setJoinInvite(data.invite);
      await refreshPhraseStatus();
      logLine("PHRASE", "opened");
    } catch (err) {
      logLine("PHRASE", (err as Error).message);
    }
  }, [fetchWithAuth, phrasePassphrase, refreshPhraseStatus, logLine]);

  const handlePhraseClose = useCallback(async () => {
    try {
      await fetchWithAuth("/v1/phrase/close", { method: "POST" });
      setPhraseInvite("");
      setPhraseQr(null);
      setPhrasePassphrase("");
      await refreshPhraseStatus();
      logLine("PHRASE", "closed");
    } catch (err) {
      logLine("PHRASE", (err as Error).message);
    }
  }, [fetchWithAuth, refreshPhraseStatus, logLine]);

  const handlePhraseJoin = useCallback(async () => {
    if (!joinInvite.trim() || !phrasePassphrase.trim()) return;
    try {
      const res = await fetchWithAuth("/v1/phrase/join", {
        method: "POST",
        body: JSON.stringify({ invite: joinInvite.trim(), passphrase: phrasePassphrase })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      setSseEnabled(true);
      startStatusPoll();
      logLine("PHRASE", `joined ${data.status}`);
    } catch (err) {
      logLine("PHRASE", (err as Error).message);
    }
  }, [fetchWithAuth, joinInvite, phrasePassphrase, logLine, startStatusPoll]);

  const handlePasteTheme = useCallback(async () => {
    try {
      const text = await navigator.clipboard.readText();
      setPhrasePassphrase(text);
      logLine("PHRASE", "theme pasted from clipboard");
    } catch (err) {
      logLine("PHRASE", (err as Error).message);
    }
  }, [logLine]);

  const handleStartAuto = useCallback(async () => {
    if (!passphrase.trim()) {
      setWarning("Passphrase required");
      return;
    }
    try {
      if (!daemonStatus.running) {
        await handleStartDaemon();
      }
      await handleSetPassphrase();
      await handleConnectCascade();
      setSseEnabled(true);
      startStatusPoll();
      setWarning(null);
    } catch (err) {
      logLine("AUTO", (err as Error).message);
    }
  }, [
    passphrase,
    daemonStatus.running,
    handleStartDaemon,
    handleSetPassphrase,
    handleConnectCascade,
    startStatusPoll
  ]);

  const handleOffer = useCallback(async () => {
    if (!passphrase) return;
    try {
      const res = await fetchWithAuth("/v1/offer", {
        method: "POST",
        body: JSON.stringify({
          passphrase,
          include_tor: includeTorOffer,
          role_hint: offerRoleHint,
          ttl_s: offerTtl ? Number(offerTtl) : undefined
        })
      });
      const data = (await res.json()) as OfferResponse;
      setOfferResult(data);
      setOfferQr(await QRCode.toDataURL(data.offer, { width: 280, margin: 1 }));
      logLine("OFFER", `ver=${data.ver}`);
    } catch (err) {
      logLine("OFFER", (err as Error).message);
    }
  }, [fetchWithAuth, passphrase, includeTorOffer, offerRoleHint, offerTtl]);

  const handleHybridQr = useCallback(async () => {
    if (!passphrase) return;
    try {
      const res = await fetchWithAuth("/v1/qr/hybrid", {
        method: "POST",
        body: JSON.stringify({
          passphrase,
          include_tor: hybridIncludeTor,
          role_hint: hybridRoleHint,
          ttl_s: hybridQrTtl ? Number(hybridQrTtl) : undefined,
          resume_ttl_s: hybridResumeTtl ? Number(hybridResumeTtl) : undefined,
          relay_hints: hybridRelayHints
            ? hybridRelayHints.split(",").map((s) => s.trim()).filter(Boolean)
            : undefined
        })
      });
      const data = (await res.json()) as HybridQrResponse;
      setHybridQrResult(data);
      setHybridQrImage(await QRCode.toDataURL(data.qr, { width: 280, margin: 1 }));
      logLine("QR", `hybrid ver=${data.ver}`);
    } catch (err) {
      logLine("QR", (err as Error).message);
    }
  }, [
    fetchWithAuth,
    passphrase,
    hybridIncludeTor,
    hybridRoleHint,
    hybridQrTtl,
    hybridResumeTtl,
    hybridRelayHints,
    logLine
  ]);

  const handleConnectHybridQr = useCallback(async () => {
    const qrTrim = hybridQrInput.trim();
    if (!qrTrim) return;
    try {
      const res = await fetchWithAuth("/v1/connect", {
        method: "POST",
        body: JSON.stringify({
          qr: qrTrim,
          local_role: hybridLocalRole
        })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      logLine("CONNECT", `${data.status} mode=${data.mode}`);
    } catch (err) {
      logLine("CONNECT", (err as Error).message);
    }
  }, [fetchWithAuth, hybridQrInput, hybridLocalRole, logLine]);

  useEffect(() => {
    invoke("daemon_status").then((r) => setDaemonStatus(r as DaemonStatus));
  }, []);

  useEffect(() => {
    if (!daemonStatus.running) return;
    let alive = true;
    const tick = async () => {
      while (alive) {
        try {
          const r = (await invoke("daemon_status")) as DaemonStatus;
          setDaemonStatus(r);
        } catch (err) {
          logLine("DAEMON", String(err));
        }
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }
    };
    tick();
    return () => {
      alive = false;
    };
  }, [daemonStatus.running, logLine]);

  // no token-file loading

  useEffect(() => {
    const err = daemonStatus.last_error || null;
    if (err && err !== lastDaemonError.current) {
      lastDaemonError.current = err;
      logLine("DAEMON", err);
    }
  }, [daemonStatus.last_error, logLine]);

  const universeId = useMemo(() => {
    if (!setPassResult) return "";
    const tag16 = setPassResult.tag16.toString(16).padStart(4, "0").toUpperCase();
    if (typeof setPassResult.tag8 === "number") {
      const tag8 = setPassResult.tag8.toString(16).padStart(2, "0").toUpperCase();
      return `HS-${tag16}-${tag8}`;
    }
    return `HS-${tag16}`;
  }, [setPassResult]);

  const wizardSteps = ["Daemon", "Flow", "Connect", "Chat"];
  const wizardIndex = useMemo(() => {
    if (connectStatus?.status === "connected") return 3;
    if (connectAttempted) return 2;
    if (daemonStatus.running) return 1;
    return 0;
  }, [connectStatus, connectAttempted, daemonStatus.running]);

  const phaseLabels = ["Derive", "Offer", "Dial", "Noise", "Ready"];
  const phaseState = useMemo<PhaseState[]>(() => {
    const status = (connectStatus?.status || "").toLowerCase();
    const dial = status === "connecting" || status === "connected";
    const noise = status === "connecting" || status === "connected";
    const ready = status === "connected";
    const offer = Boolean(offerResult) || Boolean(phraseInvite) || connectAttempted;
    const derive =
      Boolean(setPassResult) ||
      passphrase.trim().length > 0 ||
      phrasePassphrase.trim().length > 0;
    const flags = [derive, offer, dial, noise, ready];
    const activeIndex = flags.findIndex((f) => !f);
    return flags.map((done, idx) => {
      if (done && idx < (activeIndex === -1 ? flags.length : activeIndex)) return "done";
      if (idx === (activeIndex === -1 ? flags.length - 1 : activeIndex)) return "active";
      return "pending";
    });
  }, [
    connectStatus,
    offerResult,
    phraseInvite,
    connectAttempted,
    setPassResult,
    passphrase,
    phrasePassphrase
  ]);

  const phraseStats = useMemo(() => {
    const text = phrasePassphrase;
    const chars = text.length;
    const lines = text.length ? text.split("\n").length : 0;
    return { chars, lines };
  }, [phrasePassphrase]);

  const phases = phaseLabels.map((label, idx) => ({
    label,
    state: phaseState[idx]
  }));

  const warningBanner =
    warning ||
    (apiBind.startsWith("0.0.0.0") && unsafeExpose
      ? "API exposed: restrict network access and keep the token private."
      : null);

  const usesClassicPass =
    flowMode === "classic" || flowMode === "offer" || flowMode === "target";
  const tokenReady = Boolean(token);
  const apiReady = daemonStatus.running && tokenReady;
  const canSetPassphrase = passphrase.trim().length > 0 && apiReady;
  const canStartAuto = passphrase.trim().length > 0;

  const tokenStatus = token ? "token loaded" : "token missing";
  const daemonLabel = daemonStatus.running
    ? `running pid ${daemonStatus.pid ?? "?"}`
    : "stopped";
  const statusLabel = `${daemonLabel} | ${apiBind} | ${tokenStatus} | SSE ${sseState}`;
  const mark = (ok: boolean) => (ok ? "[x]" : "[ ]");
  const selectMode = (mode: FlowMode) => {
    setFlowMode(mode);
    setScreen("mode");
    setConnectAttempted(false);
  };

  return (
    <div className="app">
      <TopBar statusLabel={statusLabel} universeId={universeId} />
      {warningBanner && <div className="banner">{warningBanner}</div>}

      {screen === "home" ? (
        <div className="home">
          <div className="hero">
            <h1>Handshacke Matrix Console</h1>
            <p>
              Choose a connection mode. Each mode has a guided page with exact steps.
            </p>
          </div>
          <div className="mode-grid">
            {FLOW_MODES.map((mode) => (
              <div key={mode} className="mode-card" onClick={() => selectMode(mode)}>
                <div className="mode-title">{FLOW_LABELS[mode]}</div>
                <div className="mode-desc">{FLOW_DESC[mode]}</div>
                <ul className="mode-steps">
                  {FLOW_STEPS[mode].map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>
                <button className="mode-cta">Open</button>
              </div>
            ))}
          </div>
          <div className="panel">
            <h2>System Status</h2>
            <div style={{ fontSize: 13 }}>
              {connectStatus ? (
                <div>
                  status: {connectStatus.status}
                  <br />
                  mode: {connectStatus.mode}
                  <br />
                  port: {connectStatus.port ?? "-"}
                  <br />
                  peer: {connectStatus.peer ?? "-"}
                </div>
              ) : (
                "No status"
              )}
            </div>
            <div style={{ marginTop: 10, fontSize: 12 }}>
              daemon error: {daemonStatus.last_error ?? "-"}
              <br />
              daemon exit: {daemonStatus.last_exit_code ?? "-"}
            </div>
          </div>
        </div>
      ) : (
        <>
          <div className="page-header">
            <button className="secondary" onClick={() => setScreen("home")}>
              Back to modes
            </button>
            <div>
              <div className="page-title">{FLOW_LABELS[flowMode]}</div>
              <div className="page-subtitle">{FLOW_DESC[flowMode]}</div>
            </div>
          </div>

          <WizardSteps steps={wizardSteps} activeIndex={wizardIndex} />
          <PhaseBar phases={phases} />

          <div className="grid">
            <div className="panel">
              <h2>Daemon</h2>
              <label htmlFor="bind">API bind</label>
              <input
                id="bind"
                value={apiBind}
                onChange={(e) => setApiBind(e.target.value)}
              />
              <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                <button onClick={handleStartDaemon} disabled={daemonStatus.running}>
                  Start daemon
                </button>
                <button
                  className="secondary"
                  onClick={handleStopDaemon}
                  disabled={!daemonStatus.running}
                >
                  Stop daemon
                </button>
              </div>
              <label style={{ marginTop: 12, display: "block" }}>
                <input
                  type="checkbox"
                  checked={unsafeExpose}
                  onChange={(e) => setUnsafeExpose(e.target.checked)}
                />
                &nbsp;Allow unsafe expose
              </label>
              <div style={{ marginTop: 12, fontSize: 12 }}>
                Token: {token ? "loaded" : "missing"}
              </div>
              <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                <button className="secondary" onClick={handleFetchDaemonLogs}>
                  Fetch daemon logs
                </button>
              </div>
            </div>

            <div className="panel">
              <h2>Advanced Settings</h2>
              <div className="field-block">
                <div className="field-label">Pluggable transport</div>
                <div className="mode-row">
                  {PLUGGABLE_TRANSPORTS.map((pt) => (
                    <div
                      key={pt}
                      className={`mode-pill ${pluggableTransport === pt ? "active" : ""}`}
                      onClick={() => setPluggableTransport(pt)}
                    >
                      {pt}
                    </div>
                  ))}
                </div>
              </div>
              <input
                placeholder="RealTLS domain (optional)"
                value={realTlsDomain}
                onChange={(e) => setRealTlsDomain(e.target.value)}
              />
              <div className="helper-text">RealTLS overrides pluggable transport.</div>
              <div className="field-block">
                <div className="field-label">Stealth mode</div>
                <div className="mode-row">
                  {STEALTH_MODES.map((mode) => (
                    <div
                      key={mode}
                      className={`mode-pill ${stealthMode === mode ? "active" : ""}`}
                      onClick={() => setStealthMode(mode)}
                    >
                      {mode}
                    </div>
                  ))}
                </div>
              </div>
              <textarea
                rows={2}
                placeholder="Assist relays (comma-separated, max 5)"
                value={assistRelays}
                onChange={(e) => setAssistRelays(e.target.value)}
              />
              <input
                placeholder="Tor SOCKS address (host:port)"
                value={torSocksAddr}
                onChange={(e) => setTorSocksAddr(e.target.value)}
              />
              <input
                placeholder="Tor onion address (client target)"
                value={torOnionAddr}
                onChange={(e) => setTorOnionAddr(e.target.value)}
              />
              <div className="helper-text">Restart daemon to apply changes.</div>
            </div>

            {usesClassicPass && (
              <div className="panel">
                <h2>Passphrase (Classic/Offer/Target)</h2>
                <input
                  type={showPassphrase ? "text" : "password"}
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                />
                {!apiReady && (
                  <div className="helper-text">Start daemon and load token before setting.</div>
                )}
                <div className="universe-note">
                  Universe ID: {universeId || "HS-UNSET"}
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                  <button className="secondary" onClick={() => setShowPassphrase((v) => !v)}>
                    {showPassphrase ? "Hide" : "Show"}
                  </button>
                  <button onClick={handleSetPassphrase} disabled={!canSetPassphrase}>
                    Set
                  </button>
                </div>
                {setPassResult && (
                  <div style={{ marginTop: 12, fontSize: 12 }}>
                    port={setPassResult.port} tag16={setPassResult.tag16}
                    {typeof setPassResult.tag8 === "number"
                      ? ` tag8=${setPassResult.tag8}`
                      : ""}
                  </div>
                )}
              </div>
            )}

        {flowMode === "classic" && (
          <div className="panel">
            <h2>Classic Cascade</h2>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${passphrase.trim() ? "done" : ""}`}>
                {mark(passphrase.trim().length > 0)} Passphrase set
              </div>
              <div className={`check-item ${connectAttempted ? "done" : ""}`}>
                {mark(connectAttempted)} Connect attempted
              </div>
            </div>
            <ol className="flow-steps">
              <li>Enter passphrase and press Set</li>
              <li>Select WAN mode + Tor role</li>
              <li>Connect (LAN to WAN to Assist to Tor fallback)</li>
            </ol>
            <div className="field-block">
              <div className="field-label">Local role</div>
              <div className="mode-row">
                {ROLE_OPTIONS.map((r) => (
                  <div
                    key={r}
                    className={`mode-pill ${localRole === r ? "active" : ""}`}
                    onClick={() => setLocalRole(r)}
                  >
                    {r}
                  </div>
                ))}
              </div>
            </div>
            <div className="field-block">
              <div className="field-label">WAN mode</div>
              <div className="mode-row">
                {WAN_MODES.map((m) => (
                  <div
                    key={m}
                    className={`mode-pill ${wanMode === m ? "active" : ""}`}
                    onClick={() => setWanMode(m)}
                  >
                    {m}
                  </div>
                ))}
              </div>
            </div>
            <div className="field-block">
              <div className="field-label">Tor role</div>
              <div className="mode-row">
                {TOR_ROLES.map((r) => (
                  <div
                    key={r}
                    className={`mode-pill ${torRole === r ? "active" : ""}`}
                    onClick={() => setTorRole(r)}
                  >
                    {r}
                  </div>
                ))}
              </div>
            </div>
            {(wanMode === "tor" || wanMode === "auto") && torRole === "client" && (
              <input
                placeholder="target_onion (required for Tor client)"
                value={targetOnion}
                onChange={(e) => setTargetOnion(e.target.value)}
              />
            )}
            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <button onClick={handleConnectCascade} disabled={!passphrase.trim() || !apiReady}>
                Connect cascade
              </button>
              <button onClick={handleStartAuto} className="secondary" disabled={!canStartAuto}>
                Quick start
              </button>
            </div>
          </div>
        )}

        {flowMode === "offer" && (
          <div className="panel">
            <h2>Offer QR</h2>
            <div className="helper-text">
              The QR is a rendezvous envelope (endpoints + timing). It does NOT contain your
              passphrase. Use it for fast pairing without typing addresses.
            </div>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${passphrase.trim() ? "done" : ""}`}>
                {mark(passphrase.trim().length > 0)} Passphrase set
              </div>
              <div className={`check-item ${offerResult ? "done" : ""}`}>
                {mark(Boolean(offerResult))} Offer generated
              </div>
            </div>
            <ol className="flow-steps">
              <li>Host generates offer (QR)</li>
              <li>Client scans offer</li>
              <li>Client connects via offer</li>
            </ol>
            <div className="field-block">
              <div className="field-label">Role hint (host)</div>
              <div className="mode-row">
                {["host", "client"].map((r) => (
                  <div
                    key={r}
                    className={`mode-pill ${offerRoleHint === r ? "active" : ""}`}
                    onClick={() => setOfferRoleHint(r as "host" | "client")}
                  >
                    {r}
                  </div>
                ))}
              </div>
            </div>
            <label style={{ display: "block", marginBottom: 6 }}>
              <input
                type="checkbox"
                checked={includeTorOffer}
                onChange={(e) => setIncludeTorOffer(e.target.checked)}
              />
              &nbsp;Include Tor endpoint
            </label>
            <input
              placeholder="TTL seconds (optional)"
              value={offerTtl}
              onChange={(e) => setOfferTtl(e.target.value)}
            />
            <div className="qr-box" style={{ marginTop: 12 }}>
              <button onClick={handleOffer} disabled={!apiReady || !passphrase.trim()}>
                Generate offer QR
              </button>
              {offerQr && <img src={offerQr} alt="offer qr" />}
              {offerResult && <textarea rows={4} value={offerResult.offer} readOnly />}
              {offerResult && (
                <div className="helper-text">
                  Expires in {formatTtl(offerResult.expires_at_ms)}. Endpoints:{" "}
                  {offerResult.endpoints.join(", ")}
                </div>
              )}
              {offerResult && (
                <div style={{ display: "flex", gap: 8 }}>
                  <button
                    className="secondary"
                    onClick={() => navigator.clipboard.writeText(offerResult.offer)}
                  >
                    Copy
                  </button>
                  <button className="secondary" onClick={handleOffer}>
                    Regenerate
                  </button>
                </div>
              )}
            </div>
            <div style={{ marginTop: 12 }}>
              <input
                placeholder="paste offer"
                value={classicOffer}
                onChange={(e) => setClassicOffer(e.target.value)}
              />
              <div className="field-block">
                <div className="field-label">Local role (client)</div>
                <div className="mode-row">
                  {["host", "client"].map((r) => (
                    <div
                      key={r}
                      className={`mode-pill ${offerLocalRole === r ? "active" : ""}`}
                      onClick={() => setOfferLocalRole(r as "host" | "client")}
                    >
                      {r}
                    </div>
                  ))}
                </div>
              </div>
              <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                <button className="secondary" onClick={() => setClassicOffer("")}>
                  Clear offer
                </button>
                <button onClick={handleConnectOffer} disabled={!apiReady || !classicOffer.trim()}>
                  Connect via offer
                </button>
              </div>
            </div>
          </div>
        )}

        {flowMode === "hybrid" && (
          <div className="panel">
            <h2>Hybrid QR (Resume + Fallback)</h2>
            <div className="helper-text">
              Hybrid QR adds a resume token for fast re-join while keeping the deterministic
              fallback offer inside. This is the most robust QR flow.
            </div>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${passphrase.trim() ? "done" : ""}`}>
                {mark(passphrase.trim().length > 0)} Passphrase set
              </div>
              <div className={`check-item ${hybridQrResult ? "done" : ""}`}>
                {mark(Boolean(hybridQrResult))} Hybrid QR generated
              </div>
            </div>
            <ol className="flow-steps">
              <li>Host generates Hybrid QR</li>
              <li>Client scans QR</li>
              <li>Client connects (resume if possible, fallback otherwise)</li>
            </ol>
            <div className="field-block">
              <div className="field-label">Role hint (host)</div>
              <div className="mode-row">
                {["host", "client"].map((r) => (
                  <div
                    key={r}
                    className={`mode-pill ${hybridRoleHint === r ? "active" : ""}`}
                    onClick={() => setHybridRoleHint(r as "host" | "client")}
                  >
                    {r}
                  </div>
                ))}
              </div>
            </div>
            <label style={{ display: "block", marginBottom: 6 }}>
              <input
                type="checkbox"
                checked={hybridIncludeTor}
                onChange={(e) => setHybridIncludeTor(e.target.checked)}
              />
              &nbsp;Include Tor endpoint
            </label>
            <div className="field-block">
              <div className="field-label">QR TTL (seconds)</div>
              <input
                placeholder="QR TTL seconds (optional)"
                value={hybridQrTtl}
                onChange={(e) => setHybridQrTtl(e.target.value)}
              />
            </div>
            <div className="field-block">
              <div className="field-label">Resume TTL (seconds)</div>
              <input
                placeholder="Resume TTL seconds (optional)"
                value={hybridResumeTtl}
                onChange={(e) => setHybridResumeTtl(e.target.value)}
              />
            </div>
            <textarea
              rows={2}
              placeholder="Relay hints (comma-separated)"
              value={hybridRelayHints}
              onChange={(e) => setHybridRelayHints(e.target.value)}
            />
            <div className="qr-box" style={{ marginTop: 12 }}>
              <button onClick={handleHybridQr} disabled={!apiReady || !passphrase.trim()}>
                Generate hybrid QR
              </button>
              {hybridQrImage && <img src={hybridQrImage} alt="hybrid qr" />}
              {hybridQrResult && <textarea rows={4} value={hybridQrResult.qr} readOnly />}
              {hybridQrResult && (
                <div className="helper-text">
                  QR expires in {formatTtl(hybridQrResult.expires_at_ms)}. Resume expires in{" "}
                  {formatTtl(hybridQrResult.resume_expires_at_ms)}. Endpoints:{" "}
                  {hybridQrResult.endpoints.join(", ")}
                </div>
              )}
              {hybridQrResult && (
                <div style={{ display: "flex", gap: 8 }}>
                  <button
                    className="secondary"
                    onClick={() => navigator.clipboard.writeText(hybridQrResult.qr)}
                  >
                    Copy QR
                  </button>
                  <button className="secondary" onClick={handleHybridQr}>
                    Regenerate
                  </button>
                </div>
              )}
            </div>
            <div style={{ marginTop: 12 }}>
              <input
                placeholder="paste hybrid QR"
                value={hybridQrInput}
                onChange={(e) => setHybridQrInput(e.target.value)}
              />
              <div className="field-block">
                <div className="field-label">Local role (client)</div>
                <div className="mode-row">
                  {["host", "client"].map((r) => (
                    <div
                      key={r}
                      className={`mode-pill ${hybridLocalRole === r ? "active" : ""}`}
                      onClick={() => setHybridLocalRole(r as "host" | "client")}
                    >
                      {r}
                    </div>
                  ))}
                </div>
              </div>
              <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                <button className="secondary" onClick={() => setHybridQrInput("")}>
                  Clear QR
                </button>
                <button
                  onClick={handleConnectHybridQr}
                  disabled={!apiReady || !hybridQrInput.trim()}
                >
                  Connect via QR
                </button>
              </div>
            </div>
          </div>
        )}

        {flowMode === "target" && (
          <div className="panel">
            <h2>Target Direct</h2>
            <div className="helper-text">
              Direct target is fragile behind NAT/firewall. If this fails, prefer Offer/Hybrid QR
              with Tor relay.
            </div>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${passphrase.trim() ? "done" : ""}`}>
                {mark(passphrase.trim().length > 0)} Passphrase set
              </div>
              <div className={`check-item ${classicTarget.trim() ? "done" : ""}`}>
                {mark(classicTarget.trim().length > 0)} Target filled
              </div>
            </div>
            <ol className="flow-steps">
              <li>Enter passphrase and press Set</li>
              <li>Enter target address</li>
              <li>Connect directly</li>
            </ol>
            <input
              placeholder="target ip:port or onion:port"
              value={classicTarget}
              onChange={(e) => setClassicTarget(e.target.value)}
            />
            <label style={{ display: "block", marginTop: 8 }}>
              <input
                type="checkbox"
                checked={targetIsOnion}
                onChange={(e) => setTargetIsOnion(e.target.checked)}
              />
              &nbsp;Target is .onion (use Tor)
            </label>
            <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
              <button className="secondary" onClick={() => setClassicTarget("")}>
                Clear target
              </button>
              <button
                onClick={handleConnectTarget}
                disabled={!apiReady || !passphrase.trim() || !classicTarget.trim()}
              >
                Connect via target
              </button>
            </div>
          </div>
        )}

        {flowMode === "phrase" && (
          <div className="panel">
            <h2>Easy Tor (Phrase)</h2>
            <div className="helper-text">
              The QR invite does NOT include the passphrase. Share the QR and send the passphrase
              privately.
            </div>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${phrasePassphrase.trim() ? "done" : ""}`}>
                {mark(phrasePassphrase.trim().length > 0)} Passphrase set
              </div>
              <div className={`check-item ${phraseInvite ? "done" : ""}`}>
                {mark(Boolean(phraseInvite))} Invite generated
              </div>
            </div>
            <ol className="flow-steps">
              <li>Host opens phrase</li>
              <li>Share invite QR</li>
              <li>Client joins with passphrase</li>
            </ol>
            <textarea
              placeholder="Passphrase (private, not in QR)"
              rows={3}
              value={phrasePassphrase}
              onChange={(e) => setPhrasePassphrase(e.target.value)}
            />
            <div style={{ marginTop: 6, fontSize: 12 }}>
              {phraseStats.chars} chars / {phraseStats.lines} lines
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={handlePhraseOpen} disabled={!apiReady || !phrasePassphrase.trim()}>
                Open phrase
              </button>
              <button className="secondary" onClick={handlePasteTheme}>
                Paste
              </button>
              <button className="secondary" onClick={handlePhraseClose} disabled={!apiReady}>
                Close
              </button>
              <button className="secondary" onClick={() => setPhrasePassphrase("")}>
                Clear
              </button>
              <button className="secondary" onClick={refreshPhraseStatus} disabled={!apiReady}>
                Status
              </button>
            </div>
            <div style={{ marginTop: 10, fontSize: 12 }}>
              Status: {phraseStatus}
            </div>
            <div className="qr-box" style={{ marginTop: 12 }}>
              {phraseQr && <img src={phraseQr} alt="phrase qr" />}
              {phraseInvite && <textarea rows={4} value={phraseInvite} readOnly />}
              {phraseInvite && (
                <button
                  className="secondary"
                  onClick={() => navigator.clipboard.writeText(phraseInvite)}
                >
                  Copy invite
                </button>
              )}
            </div>
            <div style={{ marginTop: 12 }}>
              <input
                placeholder="paste invite"
                value={joinInvite}
                onChange={(e) => setJoinInvite(e.target.value)}
              />
              <button style={{ marginTop: 8 }} onClick={handlePhraseJoin} disabled={!apiReady}>
                Join phrase
              </button>
            </div>
          </div>
        )}

        {flowMode === "guaranteed" && (
          <div className="panel">
            <h2>Guaranteed Relay</h2>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${guaranteedPassphrase.trim() ? "done" : ""}`}>
                {mark(guaranteedPassphrase.trim().length > 0)} Passphrase set
              </div>
            </div>
            <ol className="flow-steps">
              <li>Enter passphrase</li>
              <li>Select egress (public/Tor)</li>
              <li>Connect via relay</li>
            </ol>
            <textarea
              placeholder="Passphrase"
              rows={2}
              value={guaranteedPassphrase}
              onChange={(e) => setGuaranteedPassphrase(e.target.value)}
            />
            <input
              placeholder="Relay URL (optional)"
              value={guaranteedRelayUrl}
              onChange={(e) => setGuaranteedRelayUrl(e.target.value)}
            />
            <div className="field-block">
              <div className="field-label">Egress</div>
              <div className="mode-row">
                {GUARANTEED_EGRESS.map((eg) => (
                  <div
                    key={eg}
                    className={`mode-pill ${guaranteedEgress === eg ? "active" : ""}`}
                    onClick={() => setGuaranteedEgress(eg)}
                  >
                    {eg}
                  </div>
                ))}
              </div>
            </div>
            <button
              onClick={handleConnectGuaranteed}
              disabled={!apiReady || !guaranteedPassphrase.trim()}
            >
              Connect guaranteed
            </button>
          </div>
        )}

        <div className="panel">
          <h2>Status</h2>
          <div style={{ fontSize: 13 }}>
            {connectStatus ? (
              <div>
                status: {connectStatus.status}
                <br />
                mode: {connectStatus.mode}{" "}
                <span className={`badge badge-${modeBadge.tone}`}>{modeBadge.label}</span>
                <br />
                port: {connectStatus.port ?? "-"}
                <br />
                peer: {connectStatus.peer ?? "-"}
                <br />
                resume: {connectStatus.resume_status ?? "-"}
              </div>
            ) : (
              "No status"
            )}
          </div>
          {connectStatus?.mode === "wan_tcp" && (
            <div className="warning-text" style={{ marginTop: 8 }}>
              UDP blocked detected. TCP fallback active. For reliability, prefer Offer/Hybrid QR
              with Tor relay.
            </div>
          )}
          {connectStatus?.mode === "wan_tor" && (
            <div className="helper-text" style={{ marginTop: 8 }}>
              Tor/relay transport active. Stable but higher latency.
            </div>
          )}
          <div style={{ marginTop: 10, fontSize: 12 }}>
            daemon error: {daemonStatus.last_error ?? "-"}
            <br />
            daemon exit: {daemonStatus.last_exit_code ?? "-"}
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <button className="secondary" onClick={refreshStatus} disabled={!apiReady}>
              Refresh
            </button>
            <button className="secondary" onClick={() => setSseEnabled(true)} disabled={!apiReady}>
              Start SSE
            </button>
            <button className="secondary" onClick={() => setSseEnabled(false)} disabled={!apiReady}>
              Stop SSE
            </button>
          </div>
        </div>

        <div className="panel">
          <h2>Network Diagnostics</h2>
          <div className="helper-text">
            This panel reflects live, RAM-only diagnostics. No data is persisted.
          </div>
          <div style={{ fontSize: 13, marginTop: 8 }}>
            {metrics ? (
              <div>
                health: {metrics.status} ({metrics.health_score}){" "}
                <span className={`badge badge-${healthBadge.tone}`}>{healthBadge.label}</span>
                <br />
                nat_type: {metrics.connection.nat_type ?? "-"}
                <br />
                transport: {metrics.connection.transport_mode}
                <br />
                throughput: {metrics.throughput_mbps.toFixed(3)} MB/s
                <br />
                packet_loss: {metrics.connection.packet_loss_rate.toFixed(2)}%
                <br />
                encrypt_avg: {metrics.connection.avg_encrypt_us.toFixed(1)} µs
                <br />
                decrypt_avg: {metrics.connection.avg_decrypt_us.toFixed(1)} µs
                <br />
                connection_errors: {metrics.connection.connection_errors}
              </div>
            ) : (
              "No diagnostics"
            )}
          </div>
          {isSymmetricNat && (
            <div className="warning-text" style={{ marginTop: 8 }}>
              Symmetric NAT detected. Direct paths are unreliable. Prefer Offer/Hybrid QR with Tor
              relay.
            </div>
          )}
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <button className="secondary" onClick={handleRefreshMetrics} disabled={!apiReady}>
              Refresh diagnostics
            </button>
          </div>
        </div>

        <div className="panel">
          <h2>Pluggable Transports</h2>
          <div className="helper-text">
            Pluggables require external infrastructure. HTTP/2 and QUIC are mimicry-only.
          </div>
          <div style={{ fontSize: 13, marginTop: 8 }}>
            {pluggableCheck ? (
              <div>
                enabled: {String(pluggableCheck.pluggable_transport.enabled)}
                <br />
                status: {pluggableCheck.pluggable_transport.status}
                <br />
                real_tls: {pluggableCheck.pluggable_transport.checklist.real_tls}
                <br />
                websocket: {pluggableCheck.pluggable_transport.checklist.websocket}
                <br />
                http2: {pluggableCheck.pluggable_transport.checklist.http2}
                <br />
                quic: {pluggableCheck.pluggable_transport.checklist.quic}
              </div>
            ) : (
              "No pluggable status"
            )}
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <button className="secondary" onClick={handleRefreshPluggable} disabled={!apiReady}>
              Refresh pluggables
            </button>
          </div>
        </div>
      </div>
    </>
  )}

      {screen === "mode" && (
        <ConsolePanel
          logs={filtered}
          filter={filter}
          onFilterChange={setFilter}
          onClear={clear}
        />
      )}
    </div>
  );
}



