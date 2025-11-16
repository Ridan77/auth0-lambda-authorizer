const { JwtVerifier } = require('aws-jwt-verify');

const issuer = process.env.AUTH0_ISSUER_BASE_URL || '';
const audience = process.env.AUTH0_AUDIENCE || '';

if (!issuer || !audience) {
  throw new Error('Missing AUTH0_ISSUER_BASE_URL or AUTH0_AUDIENCE env var');
}

const jwksUri = `${issuer.replace(/\/$/, '')}/.well-known/jwks.json`;

const verifier = JwtVerifier.create({
  issuer,
  audience,
  jwksUri,
});

function getBearerToken(authHeader) {
  if (!authHeader) return null;
  const [scheme, token] = authHeader.split(' ');
  if (!scheme || !token || scheme.toLowerCase() !== 'bearer') return null;
  return token;
}

exports.handler = async (event) => {
  try {
    if (event.requestContext?.http?.method === 'OPTIONS') {
      return { isAuthorized: true, context: { preflight: 'true' } };
    }

    const headers = event.headers || {};
    const token =
      getBearerToken(headers.authorization) ||
      getBearerToken(headers.Authorization);

    if (!token) {
      return { isAuthorized: false };
    }

    const payload = await verifier.verify(token);

    return {
      isAuthorized: true,
      context: {
        sub: String(payload.sub ?? ''),
        aud: Array.isArray(payload.aud)
          ? payload.aud.join(',')
          : String(payload.aud ?? ''),
        iss: String(payload.iss ?? ''),
        scope: String(payload.scope ?? ''),
      },
    };
  } catch (err) {
    console.error('Authorization failed:', err);
    return { isAuthorized: false };
  }
};