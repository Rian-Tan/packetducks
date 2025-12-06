
    export const getRecommendations = (threatType: string, details: any): string[] => {
    switch (threatType) {
        case 'IOC_IP':
        return [
            `Isolate Host: Immediately isolate the affected host with IP ${details.hostIp} from the network to prevent potential lateral movement.`,
            `Block Indicator: Add the malicious IP address ${details.maliciousIp} to the firewall blocklist.`,
            `Investigate Traffic: Analyze historical network traffic from the affected host to the malicious IP to identify the extent of the compromise.`,
            'Escalate: Escalate this incident to Tier 2 for further investigation and malware analysis.',
        ];
        case 'IOC_PORT':
        return [
            `Investigate Process: Identify the process on host ${details.hostIp} that is communicating on the suspicious port ${details.port}.`,
            `Review Firewall Rules: Review firewall rules for traffic on port ${details.port} and block if it is not a legitimate business requirement.`,
            'Scan for Malware: Perform a full malware scan on the affected host.',
        ];
        case 'SQLI':
        return [
            `Block Attacker IP: Immediately block the source IP address ${details.attackerIp} at the web application firewall (WAF) or network firewall.`,
            'Isolate Web Server: Consider isolating the web server to prevent further compromise.',
            'Notify Application Team: Notify the application security team or developers about the vulnerability.',
            'Review Logs: Analyze web server and database logs for signs of successful exploitation.',
        ];
        case 'XSS':
            return [
                `Block Attacker IP: Block the source IP address ${details.attackerIp} at the WAF or network firewall.`,
                'Identify Vulnerable Page: Identify the web page where the XSS payload was injected.',
                'Notify Application Team: Notify the application security team or developers to patch the vulnerability.',
            ];
        case 'RCE':
            return [
                `Isolate Host Immediately: This is a critical alert. Isolate the affected host ${details.hostIp} from the network immediately.`,
                'Preserve Evidence: Do not turn off the machine. Preserve the system for forensic analysis.',
                'Escalate Urgently: Escalate this incident to the incident response team and Tier 2/3 SOC immediately.',
            ];
        case 'C2_CONNECTION':
            return [
                `Isolate Host: Immediately isolate the host with IP ${details.hostIp} that is communicating with the C2 server.`,
                `Block C2 Communication: Block the C2 server IP address ${details.c2Ip} and any associated domains at the firewall and proxy.`,
                'Initiate Incident Response: This is a strong indicator of compromise. Initiate the incident response process.',
                'Investigate for Malware: The host is likely compromised with malware. Investigate for the malware persistence mechanism.',
            ];
        default:
        return [
            'No specific recommendation available. General investigation is advised.',
            'Check for other signs of compromise on the host.',
            'Review network traffic for other suspicious activity.',
        ];
    }
    };
