"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { WS_URL } from "@/config/app.config";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AgentEvent {
    type: string;
    agentId: number;
    role: string;
    scanId: string;
    data: Record<string, any>;
    timestamp: number | string;
}

export interface AgentState {
    id: number;
    role: string;
    name: string;
    status: "idle" | "started" | "thinking" | "acting" | "complete" | "error";
    iteration: number;
    totalIterations: number;
    currentAction: string;
    reasoning: string;
    screenshot: string; // base64
    findings: any[];
}

export interface ScanWsState {
    connected: boolean;
    scanStatus: "running" | "completed" | "stopped" | "error";
    agents: Record<number, AgentState>;
    events: AgentEvent[];
    findings: any[];
    networkRequests: any[];
}

const AGENT_NAMES: Record<string, string> = {
    sqli: "SQL Injection",
    xss: "XSS",
    auth: "Auth Bypass",
    idor: "IDOR",
    csrf: "CSRF",
};

function defaultAgents(): Record<number, AgentState> {
    const agents: Record<number, AgentState> = {};
    const roles = [
        { id: 1, role: "sqli" },
        { id: 2, role: "xss" },
        { id: 3, role: "auth" },
        { id: 4, role: "idor" },
        { id: 5, role: "csrf" },
    ];
    for (const r of roles) {
        agents[r.id] = {
            id: r.id,
            role: r.role,
            name: AGENT_NAMES[r.role] || r.role,
            status: "idle",
            iteration: 0,
            totalIterations: 20,
            currentAction: "",
            reasoning: "",
            screenshot: "",
            findings: [],
        };
    }
    return agents;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useWebSocket(scanId: string | null) {
    const [state, setState] = useState<ScanWsState>({
        connected: false,
        scanStatus: "running",
        agents: defaultAgents(),
        events: [],
        findings: [],
        networkRequests: [],
    });

    const wsRef = useRef<WebSocket | null>(null);

    const handleEvent = useCallback((event: AgentEvent) => {
        setState((prev) => {
            const next = { ...prev };
            next.events = [...prev.events, event];

            const agentId = event.agentId;
            if (agentId && next.agents[agentId]) {
                const agent = { ...next.agents[agentId] };

                switch (event.type) {
                    case "agent.started":
                        agent.status = "started";
                        break;

                    case "agent.thinking":
                        agent.status = "thinking";
                        agent.currentAction = event.data?.status || "Thinking...";
                        break;

                    case "agent.thought":
                        agent.reasoning = event.data?.thought || "";
                        break;

                    case "agent.decision":
                        agent.status = "acting";
                        agent.iteration = event.data?.iteration || agent.iteration;
                        const d = event.data?.decision;
                        if (d) {
                            agent.currentAction = `${d.action}: ${d.selector || d.value || ""}`;
                            agent.reasoning = d.reasoning || "";
                        }
                        break;

                    case "agent.action":
                        agent.status = "acting";
                        agent.currentAction = `${event.data?.action}: ${event.data?.selector || ""}`;
                        agent.reasoning = event.data?.reasoning || agent.reasoning;
                        break;

                    case "agent.iteration":
                        agent.iteration = event.data?.iteration || agent.iteration;
                        agent.totalIterations = event.data?.total || 10;
                        break;

                    case "agent.screenshot":
                        agent.screenshot = event.data?.screenshot || "";
                        break;

                    case "agent.complete":
                        agent.status = "complete";
                        agent.findings = event.data?.findings || [];
                        break;

                    case "agent.error":
                        agent.status = "error";
                        agent.currentAction = event.data?.message || event.data?.error || "Error";
                        break;

                    case "vulnerability.found":
                        const vuln = event.data?.vulnerability || event.data;
                        agent.findings = [...agent.findings, vuln];
                        next.findings = [...prev.findings, { ...vuln, agentId, role: agent.role }];
                        break;

                    case "network.request":
                        next.networkRequests = [...prev.networkRequests.slice(-100), event.data];
                        break;
                }

                next.agents = { ...next.agents, [agentId]: agent };
            }

            // Scan-level events
            if (event.type === "scan.complete") {
                next.scanStatus = "completed";
            } else if (event.type === "scan.stopped") {
                next.scanStatus = "stopped";
            }

            return next;
        });
    }, []);

    useEffect(() => {
        if (!scanId) return;

        const url = `${WS_URL}/ws/${scanId}`;
        const ws = new WebSocket(url);
        wsRef.current = ws;

        ws.onopen = () => {
            setState((prev) => ({ ...prev, connected: true }));
        };

        ws.onmessage = (msg) => {
            try {
                const event: AgentEvent = JSON.parse(msg.data);
                handleEvent(event);
            } catch {
                // ignore non-JSON
            }
        };

        ws.onerror = () => {
            setState((prev) => ({ ...prev, connected: false }));
        };

        ws.onclose = () => {
            setState((prev) => ({ ...prev, connected: false }));
        };

        return () => {
            ws.close();
        };
    }, [scanId, handleEvent]);

    return state;
}
