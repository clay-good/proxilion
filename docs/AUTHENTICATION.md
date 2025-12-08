# Authentication Layer Documentation

Proxilion MCP Gateway does **not** implement authentication by design. This document explains why and how to properly secure your deployment.

---

## Why No Built-In Authentication?

1. **Separation of concerns**: Authentication is a complex domain with many standards (OAuth 2.0, OIDC, SAML, API keys, mTLS). Implementing all of these would bloat the gateway and introduce security risks.

2. **Enterprise integration**: Most organizations already have identity providers (Okta, Azure AD, Auth0, Keycloak). Proxilion should integrate with these, not replace them.

3. **Flexibility**: Different deployments need different auth mechanisms. A sidecar deployment might use mTLS, while a cloud deployment might use OAuth.

4. **Security**: Authentication code is a common source of vulnerabilities. By delegating to battle-tested API gateways, we reduce our attack surface.

---

## Required Architecture

**Never expose Proxilion directly to the internet or untrusted networks.**

```
Untrusted Network
       |
       v
+------------------+
| API Gateway /    |  <-- Authentication happens here
| Reverse Proxy    |      (OAuth, API keys, mTLS)
+------------------+
       |
       v (authenticated requests only)
+------------------+
| Proxilion        |  <-- Trusts user_id from upstream
| Gateway          |
+------------------+
       |
       v
+------------------+
| MCP Servers      |
+------------------+
```

---

## User Identity Flow

Proxilion receives `user_id` from the client request body:

```json
{
  "tool_call": { ... },
  "user_id": "user@company.com",
  "session_id": "session_123"
}
```

**Important**: Proxilion does NOT validate this `user_id`. Your API gateway must:

1. Authenticate the request (validate token/credentials)
2. Extract the authenticated user identity
3. Either:
   - Pass it through as `user_id` in the request body, OR
   - Inject it via header that your Proxilion client middleware reads

---

## Option 1: NGINX with OAuth2 Proxy

Use NGINX as a reverse proxy with OAuth2 Proxy for OIDC authentication.

### Architecture

```
Client (with OIDC token)
       |
       v
+------------------+
| NGINX            |
| + OAuth2 Proxy   |
+------------------+
       |
       v
+------------------+
| Proxilion        |
| Gateway :8787    |
+------------------+
```

### Configuration

**docker-compose.yml:**

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - oauth2-proxy
      - proxilion

  oauth2-proxy:
    image: quay.io/oauth2-proxy/oauth2-proxy:latest
    environment:
      - OAUTH2_PROXY_PROVIDER=oidc
      - OAUTH2_PROXY_OIDC_ISSUER_URL=https://your-idp.com/
      - OAUTH2_PROXY_CLIENT_ID=your-client-id
      - OAUTH2_PROXY_CLIENT_SECRET=your-client-secret
      - OAUTH2_PROXY_COOKIE_SECRET=your-32-byte-secret
      - OAUTH2_PROXY_EMAIL_DOMAINS=*
      - OAUTH2_PROXY_UPSTREAMS=http://proxilion:8787
      - OAUTH2_PROXY_PASS_USER_HEADERS=true
      - OAUTH2_PROXY_SET_XAUTHREQUEST=true

  proxilion:
    build: .
    environment:
      - MODE=block
      - SESSION_STORE=redis
      - REDIS_URL=redis://redis:6379

  redis:
    image: redis:7-alpine
```

**nginx.conf:**

```nginx
events {
    worker_connections 1024;
}

http {
    upstream oauth2_proxy {
        server oauth2-proxy:4180;
    }

    server {
        listen 443 ssl;
        server_name proxilion.yourcompany.com;

        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;

        location /oauth2/ {
            proxy_pass http://oauth2_proxy;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        location / {
            auth_request /oauth2/auth;
            error_page 401 = /oauth2/sign_in;

            # Pass authenticated user to Proxilion
            auth_request_set $user $upstream_http_x_auth_request_user;
            auth_request_set $email $upstream_http_x_auth_request_email;

            proxy_pass http://oauth2_proxy;
            proxy_set_header X-User $user;
            proxy_set_header X-Email $email;
        }
    }
}
```

### Client Integration

Your MCP client middleware should read the authenticated email from headers:

```typescript
// The OAuth2 proxy sets X-Email header
const userId = req.headers['x-email'] || 'anonymous';

const response = await fetch('http://proxilion:8787/analyze', {
  method: 'POST',
  body: JSON.stringify({
    tool_call: toolCall,
    user_id: userId,  // From authenticated header
    session_id: sessionId,
  }),
});
```

---

## Option 2: Kong API Gateway

Kong provides enterprise-grade API management with multiple auth plugins.

### Architecture

```
Client (with API key or JWT)
       |
       v
+------------------+
| Kong Gateway     |
| (auth plugins)   |
+------------------+
       |
       v
+------------------+
| Proxilion        |
| Gateway :8787    |
+------------------+
```

### Configuration

**docker-compose.yml:**

```yaml
version: '3.8'

services:
  kong:
    image: kong:latest
    environment:
      - KONG_DATABASE=off
      - KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml
      - KONG_PROXY_LISTEN=0.0.0.0:8000, 0.0.0.0:8443 ssl
    ports:
      - "8000:8000"
      - "8443:8443"
    volumes:
      - ./kong.yml:/etc/kong/kong.yml:ro

  proxilion:
    build: .
    environment:
      - MODE=block
      - SESSION_STORE=redis
      - REDIS_URL=redis://redis:6379

  redis:
    image: redis:7-alpine
```

**kong.yml:**

```yaml
_format_version: "3.0"

services:
  - name: proxilion
    url: http://proxilion:8787
    routes:
      - name: proxilion-route
        paths:
          - /analyze
          - /health
          - /metrics

plugins:
  # Option A: API Key authentication
  - name: key-auth
    config:
      key_names:
        - apikey
        - X-API-Key

  # Option B: JWT authentication
  - name: jwt
    config:
      claims_to_verify:
        - exp

  # Option C: OAuth 2.0
  - name: oauth2
    config:
      enable_password_grant: false
      enable_client_credentials: true
      mandatory_scope: true
      scopes:
        - proxilion:analyze

  # Rate limiting (recommended)
  - name: rate-limiting
    config:
      minute: 1000
      policy: local

consumers:
  - username: mcp-client-1
    keyauth_credentials:
      - key: your-api-key-here
```

### API Key Authentication

```bash
# Create API key for a client
curl -X POST http://kong:8001/consumers/mcp-client-1/key-auth \
  -d "key=sk-proxilion-abc123"

# Client uses the key
curl -X POST https://kong:8443/analyze \
  -H "X-API-Key: sk-proxilion-abc123" \
  -H "Content-Type: application/json" \
  -d '{"tool_call": {...}, "user_id": "user@company.com"}'
```

### JWT Authentication

```bash
# Configure JWT consumer
curl -X POST http://kong:8001/consumers/mcp-client-1/jwt \
  -d "key=your-jwt-key" \
  -d "secret=your-jwt-secret"

# Client includes JWT
curl -X POST https://kong:8443/analyze \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -d '{"tool_call": {...}, "user_id": "user@company.com"}'
```

---

## Option 3: AWS API Gateway

For AWS deployments, use API Gateway with Lambda authorizers or Cognito.

### Architecture

```
Client (with Cognito token)
       |
       v
+------------------+
| AWS API Gateway  |
| + Cognito Auth   |
+------------------+
       |
       v
+------------------+
| ALB / NLB        |
+------------------+
       |
       v
+------------------+
| ECS/EKS          |
| Proxilion        |
+------------------+
```

### Terraform Configuration

```hcl
# Cognito User Pool
resource "aws_cognito_user_pool" "proxilion" {
  name = "proxilion-users"

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }
}

resource "aws_cognito_user_pool_client" "proxilion" {
  name         = "proxilion-client"
  user_pool_id = aws_cognito_user_pool.proxilion.id

  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]

  generate_secret = true
}

# API Gateway
resource "aws_apigatewayv2_api" "proxilion" {
  name          = "proxilion-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.proxilion.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "cognito-authorizer"

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.proxilion.id]
    issuer   = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.proxilion.id}"
  }
}

resource "aws_apigatewayv2_route" "analyze" {
  api_id             = aws_apigatewayv2_api.proxilion.id
  route_key          = "POST /analyze"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
  target             = "integrations/${aws_apigatewayv2_integration.proxilion.id}"
}

resource "aws_apigatewayv2_integration" "proxilion" {
  api_id                 = aws_apigatewayv2_api.proxilion.id
  integration_type       = "HTTP_PROXY"
  integration_uri        = "http://${aws_lb.proxilion.dns_name}:8787/analyze"
  integration_method     = "POST"
  payload_format_version = "2.0"
}
```

### Client Integration

```typescript
import { CognitoIdentityProviderClient, InitiateAuthCommand } from "@aws-sdk/client-cognito-identity-provider";

// Get Cognito token
const cognitoClient = new CognitoIdentityProviderClient({ region: "us-east-1" });
const authResult = await cognitoClient.send(new InitiateAuthCommand({
  AuthFlow: "USER_PASSWORD_AUTH",
  ClientId: "your-client-id",
  AuthParameters: {
    USERNAME: "user@company.com",
    PASSWORD: "password",
  },
}));

const idToken = authResult.AuthenticationResult.IdToken;

// Call Proxilion via API Gateway
const response = await fetch('https://api-id.execute-api.us-east-1.amazonaws.com/analyze', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${idToken}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    tool_call: toolCall,
    user_id: 'user@company.com',  // Should match Cognito user
    session_id: sessionId,
  }),
});
```

---

## Option 4: Azure API Management

For Azure deployments, use APIM with Azure AD authentication.

### Architecture

```
Client (with Azure AD token)
       |
       v
+------------------+
| Azure APIM       |
| + Azure AD Auth  |
+------------------+
       |
       v
+------------------+
| Azure Container  |
| Instances /AKS   |
| Proxilion        |
+------------------+
```

### APIM Policy

```xml
<policies>
    <inbound>
        <base />

        <!-- Validate Azure AD JWT -->
        <validate-jwt header-name="Authorization" failed-validation-httpcode="401">
            <openid-config url="https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration" />
            <audiences>
                <audience>api://proxilion</audience>
            </audiences>
            <issuers>
                <issuer>https://sts.windows.net/{tenant-id}/</issuer>
            </issuers>
            <required-claims>
                <claim name="roles" match="any">
                    <value>Proxilion.Analyze</value>
                </claim>
            </required-claims>
        </validate-jwt>

        <!-- Extract user from JWT and inject into request -->
        <set-variable name="user_email" value="@(context.Request.Headers.GetValueOrDefault("Authorization","").Split(' ')[1].Split('.')[1].Replace('-','+').Replace('_','/').PadRight((context.Request.Headers.GetValueOrDefault("Authorization","").Split(' ')[1].Split('.')[1].Length + 3) & ~3, '='))" />

        <!-- Forward to Proxilion -->
        <set-backend-service base-url="http://proxilion-aci.eastus.azurecontainer.io:8787" />
    </inbound>

    <backend>
        <base />
    </backend>

    <outbound>
        <base />
    </outbound>
</policies>
```

---

## Option 5: mTLS (Mutual TLS)

For internal/service-to-service communication, use mutual TLS.

### Architecture

```
MCP Client (with client certificate)
       |
       v (mTLS)
+------------------+
| NGINX / Envoy    |
| (mTLS termination)
+------------------+
       |
       v
+------------------+
| Proxilion        |
| Gateway :8787    |
+------------------+
```

### NGINX mTLS Configuration

```nginx
server {
    listen 443 ssl;
    server_name proxilion.internal;

    # Server certificate
    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    # Client certificate verification
    ssl_client_certificate /etc/nginx/certs/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;

    location / {
        # Extract CN from client certificate as user_id
        set $client_cn $ssl_client_s_dn_cn;

        proxy_pass http://proxilion:8787;
        proxy_set_header X-Client-CN $client_cn;
        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
    }
}
```

### Generate Certificates

```bash
# Create CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/CN=Proxilion CA"

# Create server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=proxilion.internal"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt

# Create client certificate (one per MCP client)
openssl genrsa -out client1.key 2048
openssl req -new -key client1.key -out client1.csr \
  -subj "/CN=mcp-client-1@company.com"
openssl x509 -req -days 365 -in client1.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client1.crt

# Create PKCS12 bundle for client
openssl pkcs12 -export -out client1.p12 \
  -inkey client1.key -in client1.crt -certfile ca.crt
```

---

## API Key Management

If using API keys (simplest option), implement proper key management:

### Key Generation

```bash
# Generate secure API key
openssl rand -base64 32 | tr -d '=' | tr '+/' '-_'
# Example: sk-proxilion-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456
```

### Key Storage

Store keys securely:

| Environment | Storage |
|-------------|---------|
| Development | `.env` file (gitignored) |
| Staging | AWS Secrets Manager / Azure Key Vault |
| Production | HashiCorp Vault / AWS Secrets Manager |

### Key Rotation

Rotate keys regularly:

1. Generate new key
2. Add new key to allowed list (both old and new valid)
3. Update all clients to use new key
4. Remove old key after grace period (e.g., 7 days)

---

## Security Checklist

Before deploying to production:

- [ ] Authentication layer deployed (OAuth, API keys, or mTLS)
- [ ] TLS/SSL enabled for all connections
- [ ] API keys stored in secrets manager (not in code)
- [ ] Rate limiting configured at API gateway
- [ ] IP allowlisting for internal deployments
- [ ] Audit logging enabled at API gateway
- [ ] Key rotation procedures documented
- [ ] Incident response plan for compromised credentials

---

## Common Mistakes

### 1. Exposing Proxilion Directly

**Wrong:**
```
Internet --> Proxilion:8787
```

**Right:**
```
Internet --> API Gateway (with auth) --> Proxilion:8787
```

### 2. Trusting Client-Provided user_id

**Wrong:** Accept any `user_id` from request body without verification.

**Right:** Extract `user_id` from authenticated token/header at API gateway.

### 3. Hardcoding API Keys

**Wrong:**
```typescript
const API_KEY = "sk-proxilion-abc123"; // In source code
```

**Right:**
```typescript
const API_KEY = process.env.PROXILION_API_KEY; // From environment
```

### 4. No Rate Limiting

**Wrong:** Unlimited requests per client.

**Right:** Configure rate limits at API gateway (e.g., 1000 req/min per user).

---

## Troubleshooting

### 401 Unauthorized

1. Check token/API key is present in request
2. Verify token hasn't expired
3. Check API gateway logs for specific error
4. Ensure client ID matches authorized audience

### 403 Forbidden

1. User authenticated but lacks required role/scope
2. IP not in allowlist
3. Rate limit exceeded

### Connection Refused to Proxilion

1. Ensure Proxilion container is running
2. Check network connectivity between API gateway and Proxilion
3. Verify port 8787 is accessible
4. Check Docker network configuration

---

## Next Steps

1. Choose an authentication method based on your infrastructure
2. Deploy API gateway in front of Proxilion
3. Configure authentication plugin/module
4. Test authentication flow end-to-end
5. Enable TLS/SSL
6. Set up monitoring and alerting
7. Document key rotation procedures
