// src/authorizer.ts
import { JwtVerifier } from "aws-jwt-verify"

/**
 * REST API V1 authorizer event (TOKEN type)
 */
interface RestApiAuthorizerEvent {
  type: "TOKEN"
  authorizationToken: string
  methodArn: string
  headers?: Record<string, string>
  [key: string]: any
}

/**
 * REST API v1 response format
 */
interface RestApiAuthorizerResponse {
  principalId: string
  policyDocument: {
    Version: "2012-10-17"
    Statement: Array<{
      Action: "execute-api:Invoke"
      Effect: "Allow" | "Deny"
      Resource: string
    }>
  }
  context?: Record<string, string>
}

/**
 * Env
 */
const issuer = process.env.AUTH0_ISSUER_BASE_URL ?? ""
const audience = process.env.AUTH0_AUDIENCE ?? ""
const jwksUri = `${issuer.replace(/\/$/, "")}/.well-known/jwks.json`

// verifier
const verifier = JwtVerifier.create({
  issuer,
  audience,
  jwksUri,
})

/**
 * Extract Bearer token from "Bearer <token>"
 */
function getBearerToken(authHeader?: string | null): string | null {
  if (!authHeader || typeof authHeader !== "string") return null
  const parts = authHeader.split(" ")
  if (parts.length !== 2) return null

  const [scheme, token] = parts
  if (scheme?.toLowerCase() !== "bearer") return null
  return token
}

/**
 * REQUIRED: Standard REST API IAM policy generator
 */
function generatePolicy(
  principalId: string,
  effect: "Allow" | "Deny",
  resource: string,
  context: Record<string, string> = {}
): RestApiAuthorizerResponse {
  return {
    principalId,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [
        {
          Action: "execute-api:Invoke",
          Effect: effect,
          Resource: resource,
        },
      ],
    },
    context,
  }
}

/**
 * MAIN HANDLER — rewritten for REST API V1 authorizers
 */
export const handler = async (
  event: RestApiAuthorizerEvent
): Promise<RestApiAuthorizerResponse> => {
  try {
    const token = getBearerToken(event.authorizationToken)
    if (!token) {
      return generatePolicy("unauthorized", "Deny", event.methodArn)
    }

    const payload = await verifier.verify(token)

    return generatePolicy(payload.sub || "client", "Allow", event.methodArn, {
      sub: String(payload.sub ?? ""),
      aud: Array.isArray(payload.aud)
        ? payload.aud.join(",")
        : String(payload.aud ?? ""),
      iss: String(payload.iss ?? ""),
      scope: String((payload as any).scope ?? ""),
    })
  } catch (err) {
    console.error("Auth error:", err)
    return generatePolicy("unauthorized", "Deny", event.methodArn)
  }
}
