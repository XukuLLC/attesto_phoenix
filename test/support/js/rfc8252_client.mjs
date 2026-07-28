// A real third-party OAuth client performing the RFC 8252 (BCP 212) native-app
// dance against a live Attesto authorization server.
//
// This is the client half of the RFC 8252 §7.3 contract, and it is deliberately
// NOT hand-rolled: `openid-client` is the canonical Node OAuth 2.0 / OpenID
// Connect client, and letting it drive proves the server interoperates with an
// implementation that knows nothing about Attesto.
//
// The §7.3 behaviour under test is that the app binds an EPHEMERAL loopback
// port at runtime, so its `redirect_uri` cannot be known at registration time.
// This script really binds one (`port: 0`, kernel-assigned) and really receives
// the authorization code on it, rather than asserting against a string it made
// up.
//
// Usage: node rfc8252_client.mjs '<json-config>'
// Emits a single JSON object on stdout: {ok: true, ...} or {ok: false, error}.

import * as client from "openid-client";
import { createServer } from "node:http";
import { once } from "node:events";

const input = JSON.parse(process.argv[2]);

// Bind the loopback callback listener on a kernel-assigned port. This is the
// whole reason §7.3 exists: the port is not knowable until this moment.
async function bindLoopback(family) {
  const server = createServer();
  const host = family === "ipv6" ? "::1" : "127.0.0.1";
  server.listen(0, host);
  await once(server, "listening");
  const { port } = server.address();
  const authority = family === "ipv6" ? `[${host}]` : host;
  return { server, port, redirectUri: `http://${authority}:${port}/cb` };
}

// Wait for the user agent to arrive on the loopback listener and hand over the
// authorization response, exactly as an installed app would.
function awaitCallback(server) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("no callback within 10s")), 10_000);
    server.once("request", (req, res) => {
      clearTimeout(timer);
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
      resolve(req.url);
    });
  });
}

async function main() {
  const family = input.family || "ipv4";
  const { server, port, redirectUri } = await bindLoopback(family);

  try {
    // Construct the client configuration directly rather than via discovery:
    // the server under test issues an `https` issuer identifier (Attesto
    // requires one) while serving these endpoints over plain HTTP on a
    // loopback test port, so a discovery fetch would compare the two and
    // rightly refuse. The endpoints are supplied by the test harness.
    const config = new client.Configuration(
      {
        issuer: input.issuer,
        authorization_endpoint: input.authorization_endpoint,
        token_endpoint: input.token_endpoint,
        pushed_authorization_request_endpoint: input.par_endpoint,
        code_challenge_methods_supported: ["S256"],
      },
      input.client_id,
      undefined,
      client.None(), // RFC 8252 §8.4: a native public client authenticates with `none`.
    );

    // The harness serves plain HTTP on a loopback port; permit it.
    client.allowInsecureRequests(config);

    // RFC 7636 / RFC 8252 §8.1: PKCE is mandatory for a native app.
    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    const state = client.randomState();

    const params = {
      redirect_uri: redirectUri,
      scope: input.scope || "openid",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
    };

    const authUrl = input.use_par
      ? await client.buildAuthorizationUrlWithPAR(config, params)
      : client.buildAuthorizationUrl(config, params);

    // Stand in for the external user agent: follow the authorization request
    // and let it redirect onto the loopback listener bound above. The server's
    // login/consent hooks are stubbed to resolve without UI, so a single hop
    // produces the redirect.
    const authResponse = await fetch(authUrl.href, { redirect: "manual" });
    const location = authResponse.headers.get("location");

    if (!location) {
      const body = await authResponse.text();
      throw new Error(
        `authorization endpoint returned ${authResponse.status} with no Location; body: ${body.slice(0, 300)}`,
      );
    }

    // Drive the redirect into the real listener, proving the ephemeral port the
    // app bound is the one the code was actually delivered to.
    const callbackPromise = awaitCallback(server);
    await fetch(location, { redirect: "manual" });
    const callbackPath = await callbackPromise;

    const currentUrl = new URL(callbackPath, redirectUri);

    // Redeem the code. openid-client verifies `state`, the PKCE binding, and
    // (because Attesto sets `authorization_response_iss`) the RFC 9207 `iss`.
    const tokens = await client.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: codeVerifier,
      expectedState: state,
    });

    const claims = tokens.claims();

    return {
      ok: true,
      family,
      bound_port: port,
      redirect_uri: redirectUri,
      redirect_location: location,
      token_type: tokens.token_type,
      has_access_token: typeof tokens.access_token === "string" && tokens.access_token.length > 0,
      has_id_token: typeof tokens.id_token === "string",
      scope: tokens.scope ?? null,
      sub: claims?.sub ?? null,
      iss: claims?.iss ?? null,
      aud: claims?.aud ?? null,
    };
  } finally {
    server.close();
  }
}

main()
  .then((result) => {
    process.stdout.write(JSON.stringify(result));
  })
  .catch((error) => {
    // openid-client raises structured errors; surface the OAuth error code and
    // description so an Elixir-side failure is diagnosable without re-running
    // the script by hand.
    process.stdout.write(
      JSON.stringify({
        ok: false,
        error: String((error && error.message) || error),
        oauth_error: error?.error ?? null,
        oauth_error_description: error?.error_description ?? null,
        status: error?.status ?? error?.response?.status ?? null,
        cause: error?.cause ? String(error.cause.message || error.cause) : null,
      }),
    );
  });
