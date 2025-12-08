// Spike Test for Proxilion MCP Gateway
//
// Purpose: Test behavior under sudden traffic spikes
// Duration: 10 minutes
// VUs: Spike from 10 to 200 users suddenly
//
// Run: k6 run loadtest/spike.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const analysisDuration = new Trend('analysis_duration');

// Test configuration with spike pattern
export const options = {
    stages: [
        { duration: '1m', target: 10 },    // Normal load
        { duration: '10s', target: 200 },  // SPIKE!
        { duration: '2m', target: 200 },   // Stay at spike
        { duration: '10s', target: 10 },   // Drop back
        { duration: '2m', target: 10 },    // Recovery period
        { duration: '10s', target: 200 },  // Second spike
        { duration: '2m', target: 200 },   // Stay at spike
        { duration: '10s', target: 0 },    // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<200'],  // Allow higher latency during spike
        errors: ['rate<0.1'],  // Allow up to 10% errors during spike
    },
};

const BASE_URL = __ENV.TARGET_URL || 'http://localhost:8787';

const payload = {
    tool_call: {
        Bash: {
            command: 'ls -la /home/user',
            args: [],
            env: {},
        },
    },
    user_id: `spike_user_${__VU}@company.com`,
    session_id: `spike_session_${__VU}_${Date.now()}`,
};

export default function () {
    const startTime = new Date();

    const response = http.post(
        `${BASE_URL}/analyze`,
        JSON.stringify(payload),
        {
            headers: {
                'Content-Type': 'application/json',
            },
            timeout: '5s',
        }
    );

    const duration = new Date() - startTime;
    analysisDuration.add(duration);

    const success = check(response, {
        'status is 200 or 403': (r) => r.status === 200 || r.status === 403,
        'response time < 1s': (r) => r.timings.duration < 1000,
    });

    errorRate.add(!success);

    // No sleep - maximize requests during spike
}

export function setup() {
    const healthResponse = http.get(`${BASE_URL}/health`);
    if (healthResponse.status !== 200) {
        throw new Error('Gateway is not healthy. Aborting spike test.');
    }
    console.log('Starting spike test - watch for recovery behavior');
}

export function teardown(data) {
    console.log('Spike test completed. Check recovery metrics.');
}
