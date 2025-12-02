# API Gateway Authorizer (Auth0 JWT Verifier)

A lightweight, production-ready **AWS API Gateway Lambda Authorizer** for verifying **Auth0-issued JWT access tokens**.  
This authorizer protects REST API (API Gateway v1) endpoints by validating incoming **Bearer tokens** using `aws-jwt-verify`, and returning an IAM policy (`Allow` or `Deny`) to API Gateway.

---

## 🚀 Features

- 🔒 Validates **Auth0 access tokens** using JWKS (JSON Web Key Set)
- ⚙️ Supports **REST API V1 TOKEN authorizers**
- 🛡️ Returns AWS IAM policies (`Allow` / `Deny`)
- 🧩 Extracts user claims into **context** (sub, aud, iss, scope)
- 🌐 Supports audience arrays (`aud: [...]`)
- ⚠️ Gracefully handles missing/invalid tokens
- 🔍 Minimal, fast, dependency-light implementation

---

## 📁 Project Structure

src/
authorizer.ts # Main Lambda Authorizer handler


---

## 🛠️ Environment Variables

These must be provided in AWS Lambda:

| Variable | Description |
|---------|-------------|
| **AUTH0_ISSUER_BASE_URL** | Your Auth0 domain (e.g. `https://cerebi-auth.us.auth0.com`) |
| **AUTH0_AUDIENCE** | API audience / identifier (e.g. `https://cerebi-api`) |

JWKS URL is inferred automatically:

https://<issuer>/.well-known/jwks.json


---

## 🔑 How the Authorizer Works

### **1. Extract the access token**
Reads the `Authorization` header:

Authorization: Bearer <access_token>

The token is extracted and validated.

---

### **2. Validate token using Auth0 + JWKS**

```ts
const payload = await verifier.verify(token)
If verification fails → the request is Denied.

3. Generate the IAM policy

Success → Allow
Failure → Deny

The allowed resource is widened to:
<methodArn>

which is required for API Gateway V1 compatibility.

4. Provide user claims to downstream Lambdas

Context returned:

{
  "sub": "<auth0 user id>",
  "aud": "<api audience>",
  "iss": "<auth0 issuer>",
  "scope": "openid profile email"
}

Your backend Lambdas receive these through:
event.requestContext.authorizer

Example Request
GET /v1/issues
Authorization: Bearer <Auth0-access-token>

🧩 Example Policy Output
✔️ Successful Verification
{
  "principalId": "auth0|691c19f2c790e2792a471647",
  "policyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "execute-api:Invoke",
        "Effect": "Allow",
        "Resource": "arn:aws:execute-api:.../GET/v1/*"
      }
    ]
  },
  "context": {
    "sub": "auth0|691c19f2c790e2792a471647",
    "aud": "https://cerebi-api",
    "iss": "https://cerebi-auth.us.auth0.com/",
    "scope": "openid profile email"
  }
}

❌ Invalid or Missing Token

{
  "principalId": "unauthorized",
  "policyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "execute-api:Invoke",
        "Effect": "Deny",
        "Resource": "<methodArn>"
      }
    ]
  }
}

🔧 Deployment
Deploy via AWS Console

Create Lambda (Node.js 18+)

Build and upload your code (dist/ folder)

Configure ENV variables

Attach Lambda to API Gateway → Authorizers

Set authorizer type to TOKEN

Add Authorization header mapping

🧪 Example Test Event (API Gateway TOKEN Authorizer)

{
  "type": "TOKEN",
  "authorizationToken": "Bearer <token>",
  "methodArn": "arn:aws:execute-api:eu-west-1:123456789012:abcd1234/dev/GET/v1/issues"
}


📝 Notes

This authorizer is for REST API (API Gateway V1)
HTTP API (v2) requires a different payload & handler.

Policy scope is widened to  to support all subroutes.

Only minimal user data is passed through context for security.

📜 License

MIT (or internal — adjust as needed)