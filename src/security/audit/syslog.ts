/**
 * Syslog / SIEM forwarder for audit events (AU 3.3.x; 800-172 SOC integration).
 *
 * Best-effort secondary sink — the authoritative, tamper-evident record is the
 * hash-chained SQLite log. Emits RFC 5424 framed messages with a JSON or CEF
 * payload over UDP or TCP. Metadata only; never CUI content.
 */

import { createSocket } from "node:dgram";
import { connect, type Socket as TcpSocket } from "node:net";
import { hostname } from "node:os";
import { logger } from "../../logger.js";
import type { StoredAuditEvent } from "../types.js";

export type SyslogConfig = {
  host: string;
  port: number;
  protocol?: "udp" | "tcp";
  format?: "json" | "cef";
};

const HOST = hostname();
const FACILITY = 13; // log audit
const SEVERITY_BY_OUTCOME: Record<string, number> = { deny: 4, error: 3 }; // warning / error
const APP = "secrouter";

function severity(e: StoredAuditEvent): number {
  return SEVERITY_BY_OUTCOME[e.outcome ?? ""] ?? 6; // informational
}

function formatCef(e: StoredAuditEvent): string {
  const ext = [
    `requestId=${e.requestId ?? ""}`,
    `suser=${e.principalId ?? ""}`,
    `src=${e.sourceIp ?? ""}`,
    `model=${e.model ?? ""}`,
    `tier=${e.tier ?? ""}`,
    `outcome=${e.outcome ?? ""}`,
    `hash=${e.hash}`,
  ].join(" ");
  return `CEF:0|Anthropic|SecRouter|1.0|${e.type}|${e.type}|${severity(e)}|${ext}`;
}

function formatMessage(e: StoredAuditEvent, format: "json" | "cef"): string {
  const pri = FACILITY * 8 + severity(e);
  const body = format === "cef" ? formatCef(e) : JSON.stringify({ ...e });
  // RFC 5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
  return `<${pri}>1 ${e.ts} ${HOST} ${APP} ${process.pid} ${e.type} - ${body}`;
}

/**
 * Build a forwarder function for the Auditor. Returns null if no config.
 */
export function makeSyslogForwarder(cfg?: SyslogConfig): ((e: StoredAuditEvent) => void) | undefined {
  if (!cfg?.host || !cfg.port) return undefined;
  const format = cfg.format ?? "json";
  const protocol = cfg.protocol ?? "udp";

  if (protocol === "udp") {
    const sock = createSocket("udp4");
    sock.unref();
    return (e) => {
      const msg = Buffer.from(formatMessage(e, format));
      sock.send(msg, cfg.port, cfg.host, (err) => {
        if (err) logger.warn(`syslog UDP send failed: ${err.message}`);
      });
    };
  }

  // TCP with octet-counting framing (RFC 6587). Lazy, reconnecting socket.
  let sock: TcpSocket | null = null;
  const ensure = (): TcpSocket => {
    if (sock && !sock.destroyed) return sock;
    sock = connect(cfg.port, cfg.host);
    sock.unref();
    sock.on("error", (err) => logger.warn(`syslog TCP error: ${err.message}`));
    return sock;
  };
  return (e) => {
    try {
      const frame = formatMessage(e, format);
      ensure().write(`${Buffer.byteLength(frame)} ${frame}`);
    } catch (err) {
      logger.warn(`syslog TCP send failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };
}
