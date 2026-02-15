export type RunStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export interface SecurityRun {
    id: string;
    created_at: string;
    status: RunStatus;
    target_url: string;
    started_at?: string;
    ended_at?: string;
}

export interface AgentSession {
    id: string;
    run_id: string;
    agent_type: string;
    status: RunStatus;
    progress: number;
    requests_used: number;
    budget: number;
}

export interface RunEvent {
    id: string;
    run_id: string;
    agent_type: string;
    event_type: 'INFO' | 'WARNING' | 'ERROR' | 'SUCCESS' | 'SCREENSHOT';
    message: string;
    data?: any;
    created_at: string;
}

export interface Finding {
    id: string;
    run_id: string;
    agent_type: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    title: string;
    evidence: string;
    recommendation: string;
    created_at: string;
}
