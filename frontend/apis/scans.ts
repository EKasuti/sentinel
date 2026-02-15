import { BASE_URL } from "@/config/app.config";

export interface StartScanResponse {
    scan_id: string;
    status: string;
    agents_spawned: number;
}

export interface ScanStatus {
    scan_id: string;
    status: string;
    target_url: string;
    findings: any[];
    agents_complete: number;
    total_agents: number;
}

export async function startScan(targetUrl: string): Promise<StartScanResponse> {
    const response = await fetch(`${BASE_URL}/api/scans/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: targetUrl }),
    });
    if (!response.ok) {
        throw new Error(`Failed to start scan: ${response.statusText}`);
    }
    return response.json();
}

export async function getScan(scanId: string): Promise<ScanStatus> {
    const response = await fetch(`${BASE_URL}/api/scans/${scanId}`);
    if (!response.ok) {
        throw new Error(`Failed to get scan: ${response.statusText}`);
    }
    return response.json();
}

export async function stopScan(scanId: string): Promise<void> {
    const response = await fetch(`${BASE_URL}/api/scans/${scanId}/stop`, {
        method: "POST",
    });
    if (!response.ok) {
        throw new Error(`Failed to stop scan: ${response.statusText}`);
    }
}
