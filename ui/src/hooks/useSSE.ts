import { useEffect, useRef, useState } from "react";

type SSEState = "idle" | "connecting" | "open" | "retrying" | "closed" | "error";

export function useSSE(
  url: string,
  opts: {
    enabled: boolean;
    headers?: Record<string, string>;
    onEvent: (evt: MessageEvent) => void;
    onOpen?: () => void;
    onError?: (err: unknown) => void;
    maxBackoffMs?: number;
  }
) {
  const { enabled, headers, onEvent, onOpen, onError, maxBackoffMs = 15000 } = opts;

  const [state, setState] = useState<SSEState>("idle");
  const backoffRef = useRef(250);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!enabled) {
      setState("idle");
      backoffRef.current = 250;
      abortRef.current?.abort();
      abortRef.current = null;
      return;
    }

    let stopped = false;

    const connect = async () => {
      if (stopped) return;

      setState((s) => (s === "open" ? "open" : "connecting"));
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;

      try {
        const res = await fetch(url, {
          method: "GET",
          headers: {
            Accept: "text/event-stream",
            ...(headers ?? {}),
          },
          signal: ac.signal,
        });

        if (!res.ok || !res.body) {
          throw new Error(`SSE HTTP ${res.status}`);
        }

        setState("open");
        backoffRef.current = 250;
        onOpen?.();

        const reader = res.body.getReader();
        const decoder = new TextDecoder("utf-8");
        let buf = "";

        while (!stopped) {
          const { value, done } = await reader.read();
          if (done) break;

          buf += decoder.decode(value, { stream: true });

          let idx;
          while ((idx = buf.indexOf("\n\n")) !== -1) {
            const chunk = buf.slice(0, idx);
            buf = buf.slice(idx + 2);

            const dataLines = chunk
              .split("\n")
              .filter((l) => l.startsWith("data:"))
              .map((l) => l.slice(5).trim());

            if (dataLines.length) {
              const data = dataLines.join("\n");
              onEvent({ data } as MessageEvent);
            }
          }
        }
      } catch (err) {
        if (stopped) return;
        setState("retrying");
        onError?.(err);

        const wait = backoffRef.current + Math.floor(Math.random() * 120);
        backoffRef.current = Math.min(backoffRef.current * 2, maxBackoffMs);

        await new Promise((r) => setTimeout(r, wait));
        if (!stopped) connect();
      }
    };

    connect();

    return () => {
      stopped = true;
      setState("closed");
      abortRef.current?.abort();
      abortRef.current = null;
    };
  }, [enabled, url, JSON.stringify(headers)]);

  return { state };
}
