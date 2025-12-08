// Soak Test for Proxilion MCP Gateway
//
// Purpose: Test long-term stability and detect memory leaks
// Duration: 1 hour
// VUs: 50 constant users
//
// Run: k6 run loadtest/soak.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Gauge } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const analysisDuration = new Trend('analysis_duration');
const activeVUs = new Gauge('active_vus');

// Test configuration for long duration
export const options = {
    stages: [
        { duration: '5m', target: 50 },   // Ramp up
        { duration: '50m', target: 50 },  // Sustained load
        { duration: '5m', target: 0 },    // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<50', 'p(99)<100'],
        errors: ['rate<0.001'],  // < 0.1% errors over long duration
        http_req_failed: ['rate<0.001'],
    },
};

const BASE_URL = __ENV.TARGET_URL || 'http://localhost:8787';

// Variety of payloads for realistic load
const payloads = [
    // File operations
    {
        tool_call: {
            Filesystem: {
                operation: 'Read',
                path: '/home/user/project/src/main.rs',
                content: null,
            },
        },
        user_id: `soak_user_${__VU}@company.com`,
        session_id: `soak_session_${__VU}`,
    },
    // Bash commands
    {
        tool_call: {
            Bash: {
                command: 'git status',
                args: [],
                env: {},
            },
        },
        user_id: `soak_user_${__VU}@company.com`,
        session_id: `soak_session_${__VU}`,
    },
    // Network requests
    {
        tool_call: {
            Network: {
                method: 'GET',
                url: 'https://api.github.com/users',
                headers: {},
                body: null,
            },
        },
        user_id: `soak_user_${__VU}@company.com`,
        session_id: `soak_session_${__VU}`,
    },
    // Database queries
    {
        tool_call: {
            Database: {
                query: 'SELECT * FROM users WHERE id = 1',
                connection: 'main',
            },
        },
        user_id: `soak_user_${__VU}@company.com`,
        session_id: `soak_session_${__VU}`,
    },
];

let requestCount = 0;

export default function () {
    activeVUs.add(__VU);

    // Rotate through payloads
    const payload = payloads[requestCount % payloads.length];
    requestCount++;

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

    const success = check(response, {
        'status is 200 or 403': (r) => r.status === 200 || r.status === 403,
        'has valid response': (r) => {
            try {
                const body = JSON.parse(r.body);
                return body.decision !== undefined;
            } catch {
                return false;
            }
        },
    });

    errorRate.add(!success);

    // Realistic pacing - 1 request per 100ms per user
    sleep(0.1);
}

export function setup() {
    const healthResponse = http.get(`${BASE_URL}/health`);
    if (healthResponse.status !== 200) {
        throw new Error('Gateway is not healthy. Aborting soak test.');
    }

    // Get initial metrics for comparison
    const metricsResponse = http.get(`${BASE_URL}/metrics`);
    console.log('Starting 1-hour soak test...');
    console.log('Monitor docker stats for memory growth');

    return {
        startTime: new Date().toISOString(),
    };
}

export function teardown(data) {
    console.log(`Soak test completed.`);
    console.log(`Started: ${data.startTime}`);
    console.log(`Ended: ${new Date().toISOString()}`);
    console.log('Check container memory usage for leaks:');
    console.log('  docker stats --no-stream proxilion-gateway');
}
