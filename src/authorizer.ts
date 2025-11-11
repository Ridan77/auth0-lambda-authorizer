// src/authorizer.ts
import type { APIGatewayRequestAuthorizerEventV2, APIGatewayAuthorizerResultV2 } from 'aws-lambda'
import { JwtRsaVerifier } from 'aws-jwt-verify'

/**
 * Env vars (set in serverless.yml):
 * - AUTH0_ISSUER_BASE_URL: e.g. https://YOUR_DOMAIN.auth0.com/
 * - AUTH0_AUDIENCE:        e.g. https://api.myapp.com
 */
const issuer = process.env.AUTH0_ISSUER_BASE_URL ?? ''
const audience = process.env.AUTH0_AUDIENCE ?? ''

// Create a singleton verifier with caching of JWKS
const verifier = JwtRsaVerifier.create({
  issuer,
  audience,
  jwksUri: `${issuer.replace(/\/$/, '')}/.well-known/jwks.json`,
  keyUse: 'sig',           // verify signature keys
  algorithms: ['RS256']
})

function getBearerToken(authHeader?: string): string | null {
  if (!authHeader) return null
  const [scheme, token] = authHeader.split(' ')
  if (!scheme || !token || scheme.toLowerCase() !== 'bearer') return null
  return token
}

export const handler = async (
  event: APIGatewayRequestAuthorizerEventV2
): Promise<APIGatewayAuthorizerResultV2> => {
  try {
    // Allow unauthenticated CORS preflight if you like:
    if (event.routeArn && event.headers?.['content-type'] === 'application/json' && event.requestContext?.http?.method === 'OPTIONS') {
      return { isAuthorized: true, context: { preflight: 'true' } }
    }

    const token = getBearerToken(event.headers?.authorization || event.headers?.Authorization as string)
    if (!token) {
      return { isAuthorized: false }
    }

    // Verify JWT (signature + iss + aud + exp)
    const payload = await verifier.verify(token)

    // Optional: you can enforce scopes/claims here
    // const scope = (payload.scope as string | undefined)?.split(' ') ?? []
    // if (!scope.includes('read:issues')) return { isAuthorized: false }

    // Attach selected claims to context (strings only)
    return {
      isAuthorized: true,
      context: {
        sub: String(payload.sub ?? ''),
        aud: Array.isArray(payload.aud) ? payload.aud.join(',') : String(payload.aud ?? ''),
        iss: String(payload.iss ?? ''),
        scope: String((payload as any).scope ?? '')
      }
    }
  } catch (err) {
    // Signature invalid, token expired, wrong iss/aud, etc.
    return { isAuthorized: false }
  }
}
