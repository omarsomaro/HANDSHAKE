import { useCallback, useMemo, useRef, useState } from "react";

export interface LogLine {
  ts: string;
  label: string;
  body: string;
}

const formatTs = () => new Date().toLocaleTimeString();

export function useLogs(limit = 300) {
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [filter, setFilter] = useState("");
  const bufferRef = useRef<LogLine[]>([]);
  const flushTimer = useRef<number | null>(null);

  const logLine = useCallback(
    (label: string, body: string) => {
      bufferRef.current.unshift({ ts: formatTs(), label, body });
      if (flushTimer.current == null) {
        flushTimer.current = window.setTimeout(() => {
          const pending = bufferRef.current;
          bufferRef.current = [];
          flushTimer.current = null;
          if (pending.length) {
            setLogs((prev) => [...pending, ...prev].slice(0, limit));
          }
        }, 100);
      }
    },
    [limit]
  );

  const clear = useCallback(() => {
    bufferRef.current = [];
    setLogs([]);
  }, []);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return logs;
    return logs.filter((line) =>
      `${line.label} ${line.body}`.toLowerCase().includes(q)
    );
  }, [logs, filter]);

  return {
    logs,
    filtered,
    filter,
    setFilter,
    logLine,
    clear
  };
}
