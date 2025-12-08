// Baseline Load Test for Proxilion MCP Gateway
//
// Purpose: Establish performance baseline with moderate load
// Duration: 5 minutes
// VUs: 10 concurrent virtual users
//
// Run: k6 run loadtest/baseline.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const analysisDuration = new Trend('analysis_duration');

// Test configuration
export const options = {
    vus: 10,
    duration: '5m',
    thresholds: {
        http_req_duration: ['p(95)<50', 'p(99)<100'],  // ms
        errors: ['rate<0.01'],  // < 1% error rate
        http_req_failed: ['rate<0.01'],
    },
};

const BASE_URL = __ENV.TARGET_URL || 'http://localhost:8787';

// Test payloads representing different threat levels
const payloads = [
    // Safe command (should score low)
    {
        tool_call: {
            Bash: {
                command: 'ls -la /home/user/projects',
                args: [],
                env: {},
            },
        },
        user_id: 'loadtest@company.com',
        session_id: `session_${__VU}_${Date.now()}`,
    },
    // Suspicious command (medium score)
    {
        tool_call: {
            Bash: {
                command: 'cat /etc/passwd',
                args: [],
                env: {},
            },
        },
        user_id: 'loadtest@company.com',
        session_id: `session_${__VU}_${Date.now()}`,
    },
    // High threat command (should score high)
    {
        tool_call: {
            Bash: {
                command: 'nmap -sV 192.168.1.0/24',
                args: [],
                env: {},
            },
        },
        user_id: 'loadtest@company.com',
        session_id: `session_${__VU}_${Date.now()}`,
    },
];

export default function () {
    // Randomly select a payload
    const payload = payloads[Math.floor(Math.random() * payloads.length)];

    const startTime = new Date();

    const response = http.post(
        `${BASE_URL}/analyze`,
        JSON.stringify(payload),
        {
            headers: {
                'Content-Type': 'application/json',
            },
        }
    );

    const duration = new Date() - startTime;
    analysisDuration.add(duration);

    // Validate response
    const success = check(response, {
        'status is 200 or 403': (r) => r.status === 200 || r.status === 403,
        'response has decision': (r) => {
            try {
                const body = JSON.parse(r.body);
                return body.decision !== undefined;
            } catch {
                return false;
            }
        },
        'response has threat_score': (r) => {
            try {
                const body = JSON.parse(r.body);
                return typeof body.threat_score === 'number';
            } catch {
                return false;
            }
        },
    });

    errorRate.add(!success);

    // Small sleep to simulate realistic request patterns
    sleep(0.1);
}

// Setup function - verify gateway is healthy
export function setup() {
    const healthResponse = http.get(`${BASE_URL}/health`);
    check(healthResponse, {
        'gateway is healthy': (r) => r.status === 200,
    });

    if (healthResponse.status !== 200) {
        throw new Error('Gateway is not healthy. Aborting test.');
    }

    console.log('Gateway health check passed. Starting load test...');
}

// Teardown function - print summary
export function teardown(data) {
    console.log('Load test completed.');
}
