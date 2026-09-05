# OAuth 2.0 and OpenID Connect — A Plain-English Overview

This is the long-form walkthrough. If you want the five-minute refresher instead, read the
[README](README.md).

Everything here is explained with analogies first and protocol details second. Read it top to
bottom once, then use it as a lookup table forever after.

---

## Contents

1. [The problem OAuth solves](#1-the-problem-oauth-solves)
2. [The cast of characters](#2-the-cast-of-characters)
3. [OAuth is not login — OpenID Connect is](#3-oauth-is-not-login--openid-connect-is)
4. [The three tokens](#4-the-three-tokens)
5. [Front channel vs. back channel](#5-front-channel-vs-back-channel)
6. [The Authorization Code flow, step by step](#6-the-authorization-code-flow-step-by-step)
7. [PKCE — the part you must not skip](#7-pkce--the-part-you-must-not-skip)
8. [The other grant types](#8-the-other-grant-types)
9. [OpenID Connect on top](#9-openid-connect-on-top)
10. [Anatomy of an ID token](#10-anatomy-of-an-id-token)
11. [`state` vs. `nonce` vs. `code_verifier`](#11-state-vs-nonce-vs-code_verifier)
12. [Validating tokens](#12-validating-tokens)
13. [Refresh, expiry, and logout](#13-refresh-expiry-and-logout)
14. [Scopes, audiences, and claims](#14-scopes-audiences-and-claims)
15. [Doing this on Android](#15-doing-this-on-android)
16. [Common mistakes](#16-common-mistakes)
17. [Glossary](#17-glossary)
18. [Spec map](#18-spec-map)

---

## 1. The problem OAuth solves

Imagine a photo-printing website that wants to print the photos you keep on Google Photos.

The obvious approach is the terrible one: the printing site asks for your Google username and
password, logs in as you, and downloads your photos. That gives a random company your actual
credentials, unlimited access to your entire account, forever, with no way to revoke it short of
changing your password.

**OAuth 2.0 is the standard way to hand out limited access to your stuff without handing over your
password.**

The analogy that sticks is the **valet key**. Some cars ship with a second key that starts the
engine and opens the driver's door, but won't open the trunk or the glovebox, and won't let the car
go above a certain speed. You give the valet that key. They can do their job. They cannot rifle
through your things or take the car to another state.

An OAuth access token is a valet key for an API:

- It is **scoped** — it grants specific permissions, not everything.
- It is **temporary** — it expires, often within an hour.
- It is **revocable** — you can cancel it without changing your password.
- It is **attributable** — it was issued to a specific app, so you can see and revoke exactly which
  apps have access.

That's the whole idea. Everything else is mechanics.

---

## 2. The cast of characters

OAuth has four roles. Confusion almost always comes from mixing up the last two.

| Role | Plain English | In the photo example |
|---|---|---|
| **Resource Owner** | The human who owns the data and can say yes or no | You |
| **Client** | The app that wants access to the data | The photo-printing site |
| **Authorization Server (AS)** | Issues tokens; runs the login and consent screens | Google's login service |
| **Resource Server (RS)** | The API holding the data; accepts tokens | The Google Photos API |

The two servers are separate roles even when the same company runs both. The authorization server
**mints** tokens. The resource server **accepts** tokens. They talk to different parts of your code
and they have different security jobs.

### Two kinds of client

This distinction drives most of the rules, so it's worth internalizing:

- A **confidential client** can keep a secret. It runs on a server you control. Nobody can read its
  memory or decompile it. It gets a `client_secret` and uses it to prove identity.
- A **public client** cannot keep a secret. Mobile apps, desktop apps, and single-page web apps are
  all public clients. Anything you ship to a user's device can be decompiled or inspected, so any
  "secret" inside it is not a secret.

**Your Android app is a public client.** It must never contain a client secret. This is not a
best-practice suggestion; it's a structural fact about shipping code to devices you don't control.

---

## 3. OAuth is not login — OpenID Connect is

This is the single most important idea in this document, and the most commonly botched one in real
codebases.

**OAuth 2.0 is about authorization ("what may this app do?"), not authentication ("who is this
person?").**

An access token says *the bearer of this token is allowed to call these APIs*. It says nothing
reliable about who the user is. Deliberately: the resource server doesn't need to know, and the
token has no defined format or audience checks that a client can rely on.

So why do people keep using OAuth for login? Because it *almost* works. You get an access token,
you call some `/me` endpoint, it returns a user ID, and you log the user in. That pattern has a real
vulnerability with a name: the **confused deputy** / token substitution problem. An access token is
a bearer token — whoever holds it can use it. A malicious app can take a token that a user granted
to *it*, hand that token to *your* app, and if your app just calls `/me` and trusts the answer, your
app logs the attacker in as that user. Nothing in the token told your app who it was issued to.

**OpenID Connect (OIDC) is a thin identity layer on top of OAuth 2.0** that fixes exactly this. It
adds a second token — the **ID token** — which is a signed statement from the authorization server
that says: *this specific user authenticated, at this time, and I minted this statement for you
specifically, in response to your specific request.* Those last two properties (`aud` and `nonce`)
are what make it safe for login when a raw access token isn't.

The mental model:

> **OAuth answers "what is this app allowed to do?"**
> **OIDC answers "who is this user, and did they just prove it?"**

Or, in physical terms: the access token is a **hotel key card** (opens certain doors, expires at
checkout, has your name nowhere on it). The ID token is your **passport** (identifies you, signed by
an authority, checked at a border — but useless for opening hotel doors).

Practical upshot: **if you are building "Sign in with X," you want OpenID Connect, not bare OAuth.**

---

## 4. The three tokens

| Token | Answers | Who reads it | Typical life | Send it to |
|---|---|---|---|---|
| **Access token** | "May the bearer do this?" | The **API** | Minutes to an hour | Resource servers |
| **ID token** | "Who logged in, and when?" | **Your app** | Minutes (used once, at login) | Nobody |
| **Refresh token** | "May I have a new access token?" | The **authorization server** | Days to months | Token endpoint only |

Three rules that follow directly from that table, and that people break constantly:

**Never send an ID token to an API as if it were an access token.** The ID token's audience (`aud`)
is your client, not the API. An API that accepts ID tokens as credentials is misconfigured. (There
are narrow, deliberate exceptions where a backend uses an ID token to establish a session — but
sending it as `Authorization: Bearer` to a general-purpose resource server is a mistake.)

**Never try to read or validate an access token in your client app.** Its format is not your
business. It might be a JWT you *could* decode, or it might be an opaque random string. Either way,
it wasn't minted for you and its contents may change without notice. Treat it as an unreadable blob
you pass along. The only party that should validate an access token is the resource server.

**Never let a refresh token touch anything except the token endpoint.** It's the long-lived one, so
it's the valuable one.

---

## 5. Front channel vs. back channel

Nearly every security rule in OAuth follows from this one distinction, so it's worth spending a
minute on.

**The front channel is the browser.** Data travels by redirect: your app sends the user to a URL,
the server sends the user back to another URL, and the data rides along in the query string. It's
like **passing a note through a crowd of strangers to reach someone across the room**. It works, but
the note is visible in browser history, in server logs, in the address bar, and potentially to any
other app on the device that registered the same redirect URI. And you have no proof of who actually
handed you the note.

**The back channel is a direct HTTPS call** from your app or server to the authorization server. No
browser, no redirects, no intermediaries. It's a **private phone call between two parties**, with
TLS confirming who's on the other end.

| | Front channel | Back channel |
|---|---|---|
| Path | Through the user's browser via redirects | Direct HTTPS |
| Visible to | Browser history, logs, address bar, other local apps | Only the two endpoints |
| Sender identity | Unverified | Verified by TLS (and client auth) |
| Safe to carry | One-time codes, public parameters | Tokens, secrets |

**The core design of modern OAuth: never put a token in the front channel.** Send a one-time,
single-use, useless-by-itself **authorization code** through the browser, then redeem that code for
tokens over the back channel.

This is exactly why the old **implicit flow** — which returned an access token directly in the URL
fragment — is now deprecated. It put the crown jewels in the note passed through the crowd.

---

## 6. The Authorization Code flow, step by step

This is *the* flow. If you learn one thing, learn this one. With PKCE added (next section), it is
the correct choice for web apps, mobile apps, SPAs, and desktop apps alike.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant App as Your App
    participant Browser
    participant AS as Authorization Server
    participant API as Resource Server

    User->>App: Taps "Sign in"
    App->>App: Create random code_verifier
    App->>App: code_challenge = SHA256(code_verifier)
    App->>Browser: Open /authorize with code_challenge and state
    Browser->>AS: GET /authorize
    AS->>User: Show login and consent screen
    User->>AS: Authenticate and approve
    AS-->>Browser: Redirect back to app with a one-time code
    Browser-->>App: Deliver the code (front channel)
    App->>App: Verify state matches what we sent
    App->>AS: POST /token with code plus code_verifier (back channel)
    AS->>AS: Check SHA256(code_verifier) equals stored code_challenge
    AS-->>App: access_token, id_token, refresh_token
    App->>API: Call API with Authorization Bearer access_token
    API-->>App: Protected data
```

### What actually goes over the wire

**Steps 4–5 — the authorization request.** Your app opens a browser to the authorization server. Line
breaks added for readability; in reality it's one URL.

```http
GET /authorize
  ?response_type=code
  &client_id=s6BhdRkqt3
  &redirect_uri=com.rick.oauthopenid%3A%2F%2Foauth2redirect
  &scope=openid%20profile%20email%20offline_access
  &state=af0ifjsldkj
  &nonce=n-0S6_WzA2Mj
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

| Parameter | What it's for |
|---|---|
| `response_type=code` | "Give me a code, not a token." The only response type you should use. |
| `client_id` | Which app is asking. Public, not a secret. |
| `redirect_uri` | Where to send the user back. Must match a pre-registered value **exactly**. |
| `scope` | What you're asking for. `openid` is what turns this into an OIDC request. |
| `state` | Anti-CSRF. Random, tied to this browser session. |
| `nonce` | Replay protection for the ID token. Random, remembered by your app. |
| `code_challenge` | The PKCE lock. See the next section. |
| `code_challenge_method=S256` | Always `S256`. Never `plain`. |

**Steps 8–9 — the redirect back.** The authorization server bounces the browser back to your
`redirect_uri`:

```
com.rick.oauthopenid://oauth2redirect?code=SplxlOBeZQQYbYS6WxSbIA&state=af0ifjsldkj
```

Before doing anything else, **compare that `state` to the one you sent.** If it doesn't match, abort.

**Step 11 — the token exchange.** Now over the back channel:

```http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=com.rick.oauthopenid%3A%2F%2Foauth2redirect
&client_id=s6BhdRkqt3
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

A confidential client would also authenticate here, typically with an `Authorization: Basic` header
carrying its client secret. Your Android app does not, because it has no secret — the `code_verifier`
is what protects it instead.

**Step 13 — the response.**

```json
{
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ...",
  "scope": "openid profile email"
}
```

**Step 14 — calling the API.** The access token goes in an `Authorization` header:

```http
GET /v1/photos HTTP/1.1
Host: api.example.com
Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA
```

Never put an access token in a query string. Query strings land in logs, browser history, and
`Referer` headers.

### Why the code-then-exchange dance?

It's a two-key system. The code travels through the risky front channel but is worthless on its own:
it's single-use, expires in about a minute, and must be redeemed with proof (a client secret, a PKCE
verifier, or both) that only the real client has. Tokens travel only over the back channel. An
attacker who steals the code from the browser still can't get tokens.

---

## 7. PKCE — the part you must not skip

Pronounced "pixie." **Proof Key for Code Exchange** ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)).

### The attack it stops

On mobile, redirect URIs are claimed by custom schemes like `com.rick.oauthopenid://`. There is
nothing stopping a malicious app from *also* registering that scheme. If it does, it may intercept
the redirect and steal your authorization code. Without PKCE, a stolen code is enough to get real
tokens, because a public client has no secret to prove it was the original requester.

### How it works

Think of it as **mailing yourself a padlock before the package ships.**

1. Before starting, your app generates a high-entropy random string: the **`code_verifier`** (43–128
   characters). This never leaves the device until the very last step.
2. It hashes it: **`code_challenge = BASE64URL(SHA256(code_verifier))`**. That's the padlock — public,
   and useless for deriving the key.
3. The challenge goes out in the front-channel authorization request. Even if an attacker reads it,
   they can't reverse SHA-256.
4. The authorization server stores the challenge alongside the code it issues.
5. When your app redeems the code over the back channel, it includes the original `code_verifier`.
6. The server hashes what it received and compares. Match, tokens. No match, rejection.

The malicious app that stole the code never saw the verifier, so it cannot complete step 5. The code
is inert in its hands.

Using the canonical test vector from the RFC, so you can verify your own implementation:

```
code_verifier  = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
code_challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
```

### Two rules

**Always use `S256`, never `plain`.** The `plain` method sends the verifier itself as the challenge,
which defeats the entire purpose against an attacker who can read the front channel.

**Use PKCE even for confidential clients.** PKCE was originally designed for mobile, and older guides
present it as a public-client-only measure. That advice is out of date. RFC 9700 and OAuth 2.1 both
call for PKCE on *all* authorization code flows, because it also defends against code injection
attacks that affect server-side clients.

---

## 8. The other grant types

### Still good

**Authorization Code + PKCE** — everything with a user in front of it. This is your default; reach
for something else only when this genuinely doesn't fit.

**Client Credentials** — machine-to-machine, no user involved. A backend service calling another
backend service. There is no resource owner to ask, so there's no browser and no redirect: the client
authenticates and gets a token directly. Confidential clients only, obviously. Never receives a
refresh token (just request a new one) and never receives an ID token (there's no user).

```http
POST /token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=client_credentials&scope=inventory.read
```

**Device Authorization Grant** ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) — for devices with
no keyboard or browser: TVs, consoles, CLI tools. The device shows a short code and a URL, you
complete login on your phone, and the device polls the token endpoint until you're done. This is
what you're using when a smart TV tells you to visit `example.com/activate` and type `WDJB-MJHT`.

**Refresh Token** — trading a refresh token for a fresh access token. Covered in
[§13](#13-refresh-expiry-and-logout).

### Deprecated — do not use

**Implicit** (`response_type=token`) — returned an access token directly in the URL fragment. Made
sense in 2012 when browsers couldn't make cross-origin calls to the token endpoint; CORS solved that
years ago. It leaks tokens into browser history and logs and offers no way to authenticate the
client. Removed in OAuth 2.1. If you find `response_type=token` in a codebase, it's a bug.

**Resource Owner Password Credentials** (ROPC) — the app collects the user's actual username and
password and posts them to the token endpoint. This throws away the entire point of OAuth: the app
sees the password, so there's no delegation, no consent screen, and no way to support MFA, federated
login, or passkeys. Also removed in OAuth 2.1.

---

## 9. OpenID Connect on top

OIDC is a **profile** of OAuth 2.0 — same endpoints, same flow, extra rules and one extra token. If
you understand the authorization code flow, you already understand 90% of OIDC. Here's the other 10%.

### 1. The `openid` scope

Add `openid` to your `scope` parameter and the request becomes an OIDC request. That's the switch.
The authorization server will now also return an `id_token`.

Common companion scopes, each of which maps to a defined set of claims:

| Scope | Gets you |
|---|---|
| `openid` | Required. Turns on OIDC; yields `sub`. |
| `profile` | `name`, `family_name`, `given_name`, `picture`, `locale`, `updated_at`, and friends |
| `email` | `email`, `email_verified` |
| `address` | `address` |
| `phone` | `phone_number`, `phone_number_verified` |
| `offline_access` | A refresh token (on many providers) |

### 2. The ID token

A signed JWT describing the authentication event. Covered in detail in
[§10](#10-anatomy-of-an-id-token).

### 3. Discovery

Rather than hardcoding endpoint URLs, fetch them from a well-known document:

```
GET https://as.example.com/.well-known/openid-configuration
```

```json
{
  "issuer": "https://as.example.com",
  "authorization_endpoint": "https://as.example.com/authorize",
  "token_endpoint": "https://as.example.com/token",
  "userinfo_endpoint": "https://as.example.com/userinfo",
  "jwks_uri": "https://as.example.com/.well-known/jwks.json",
  "end_session_endpoint": "https://as.example.com/logout",
  "response_types_supported": ["code"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "code_challenge_methods_supported": ["S256"]
}
```

`jwks_uri` is the important one: it publishes the public keys you'll use to verify ID token
signatures. Fetch and cache it, keyed by the `kid` in each token header, so key rotation doesn't
break you.

(Plain OAuth has an equivalent document at `/.well-known/oauth-authorization-server`, from
[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414).)

### 4. The UserInfo endpoint

An OAuth-protected API returning claims about the current user. Call it with the **access token**:

```http
GET /userinfo HTTP/1.1
Host: as.example.com
Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA
```

```json
{
  "sub": "248289761001",
  "name": "Rick",
  "email": "rick@example.com",
  "email_verified": true
}
```

Use it when you want profile data that may have changed since login, or to keep the ID token small.
Always confirm the `sub` it returns matches the `sub` in your ID token.

---

## 10. Anatomy of an ID token

An ID token is a **JWT**: three Base64URL chunks joined by dots — `header.payload.signature`.

Header:

```json
{ "alg": "RS256", "kid": "1e9gdk7", "typ": "JWT" }
```

Payload:

```json
{
  "iss": "https://as.example.com",
  "sub": "248289761001",
  "aud": "s6BhdRkqt3",
  "exp": 1789200000,
  "iat": 1789196400,
  "auth_time": 1789196380,
  "nonce": "n-0S6_WzA2Mj",
  "name": "Rick",
  "email": "rick@example.com",
  "email_verified": true
}
```

The five mandatory claims, and what each one is really for:

| Claim | Name | Why it exists |
|---|---|---|
| `iss` | Issuer | Who signed this. Must exactly equal your configured issuer. |
| `sub` | Subject | **The stable user ID.** Unique within the issuer, and never reused. |
| `aud` | Audience | **Who this token was minted for.** Must equal your `client_id`. |
| `exp` | Expiration | Reject after this time. |
| `iat` | Issued at | When it was minted. |

`nonce` is required whenever you sent one, which you always should.

### `sub` is the user ID — not `email`

Your primary key for a user is the pair **(`iss`, `sub`)**. Not the email address. Emails get
changed, recycled between employees, and are sometimes not verified at all. `sub` is stable and
guaranteed unique per issuer. Store both `iss` and `sub`, because `sub` values are only unique
*within* an issuer, and you may add a second identity provider later.

### Validation checklist

Before you trust a single claim, verify all of the following. A library should do this for you —
use one rather than hand-rolling it.

- [ ] The **signature** verifies against the issuer's published JWKS key (matched by `kid`).
- [ ] `alg` is an expected asymmetric algorithm from your allowlist — and specifically **not** `none`,
      and not silently downgraded to a symmetric algorithm like `HS256`. This was a real, widespread
      JWT library vulnerability.
- [ ] `iss` **exactly** matches your expected issuer string.
- [ ] `aud` contains your `client_id`. (If `azp` is present, it must be your `client_id` too.)
- [ ] `exp` is in the future, and `iat` is sane, with a small clock-skew allowance (a minute or two).
- [ ] `nonce` matches the one you generated for this specific request.

Skipping the signature check makes the token pure decoration. Skipping `aud` or `nonce` reintroduces
the substitution and replay attacks the ID token exists to prevent.

> Debugging tip: a JWT is only Base64-encoded, not encrypted. Anyone can read the payload. Never put
> anything in a token you wouldn't put on a postcard, and remember that decoding a token on a website
> to inspect it means pasting a live credential into someone else's server.

---

## 11. `state` vs. `nonce` vs. `code_verifier`

Three random values, sent in the same request, doing three completely different jobs. This trips up
almost everyone, so here they are side by side.

| | `state` | `nonce` | `code_verifier` |
|---|---|---|---|
| **Protects against** | CSRF — a forged callback | ID token replay | Code interception |
| **The question it answers** | "Is this response to a request *I* started?" | "Was this ID token minted for *this* request?" | "Am I the app that *started* this flow?" |
| **Sent in** | Authorization request, returned in redirect | Authorization request, echoed inside the ID token | Hashed in the authorization request; raw at the token endpoint |
| **Checked by** | Your app, against what it stored | Your app, against the ID token claim | The **authorization server** |
| **From** | OAuth 2.0 core | OIDC | PKCE (RFC 7636) |

The one real overlap: `code_verifier` also provides CSRF protection, as does a validated `nonce` in
OIDC flows. So OAuth 2.1 says a client *may* rely on PKCE for CSRF instead of `state` — but only if
it has confirmed the authorization server actually supports the `code_challenge_method` it's using.
If the server doesn't, `state` or `nonce` becomes mandatory again.

In practice, keep sending `state` anyway. It still does a job PKCE doesn't: carrying a bit of app
context, like the page the user was on before login, so you can return them there afterward. Just
don't put sensitive data in it (it rides the front channel), and if its contents matter, protect it
against tampering.

All three must be **cryptographically random**, generated fresh per request, and never reused.

---

## 12. Validating tokens

### The resource server's job

When an API receives `Authorization: Bearer <token>`, it has to decide whether to honor it. Two
approaches:

**Local validation (JWT access tokens).** If the access token is a signed JWT, the API verifies the
signature against the AS's JWKS and checks the claims itself. Fast, no network call per request,
scales well. The cost: revocation isn't instant, since a token stays cryptographically valid until it
expires. Keep access token lifetimes short to bound that window.
([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) standardizes the JWT access token format.)

**Introspection (opaque tokens).** The API posts the token to the AS's introspection endpoint
([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)) and gets back a verdict:

```json
{ "active": true, "scope": "photos.read", "client_id": "s6BhdRkqt3", "sub": "248289761001", "exp": 1789200000 }
```

Always current, including instant revocation. The cost: a network round trip per request, though
short-TTL caching helps.

Either way the API must check that the token is **for this API** (`aud` or the resource indicator)
and carries the **required scope** for this endpoint. A valid token for a different API is not
authorization to call yours.

### The client's job

Verify the **ID token** per [§10](#10-anatomy-of-an-id-token). Do not inspect the access token.

---

## 13. Refresh, expiry, and logout

### Why access tokens expire quickly

Short lifetimes limit the blast radius of a leaked token. If one escapes into a log file, it's dead
in an hour. The refresh token is what keeps the user from having to log in again — it lives at rest
in your app's secure storage rather than being sent to APIs, so it's exposed far less often.

```mermaid
sequenceDiagram
    autonumber
    participant App as Your App
    participant AS as Authorization Server
    participant API as Resource Server

    App->>API: Request with expired access token
    API-->>App: 401 Unauthorized
    App->>AS: POST /token with grant_type refresh_token
    AS-->>App: New access token and rotated refresh token
    App->>API: Retry original request
    API-->>App: 200 OK
```

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
&client_id=s6BhdRkqt3
```

Implementation notes that matter in practice: refresh **on a 401**, or slightly before expiry — don't
schedule a timer and hope. And make sure concurrent requests don't each fire their own refresh;
funnel them through a single-flight mutex, or a burst of parallel calls after expiry will trigger a
stampede of refreshes and, under rotation, invalidate each other.

### Refresh token rotation

For public clients, RFC 9700 requires refresh tokens to be either **sender-constrained** or
**rotated**. Rotation means every refresh returns a *new* refresh token and retires the old one.

The clever part is what rotation gives you for free: **theft detection.** If a stolen refresh token
gets used, then the legitimate app later tries its copy — or vice versa — the AS sees an already-used
token from that family and revokes the entire chain. Both parties are logged out, and the user
re-authenticates. An attacker can't quietly maintain access indefinitely.

So: **always store the new refresh token from every response.** Reusing the old one will eventually
log your user out and look like a mystery bug.

### Logging out

"Log out" is ambiguous, and this catches people. There are three distinct levels:

1. **Clear local tokens.** Delete them from your app's storage. The user appears logged out — but if
   they hit "sign in" again, the AS still has an active session and may log them straight back in
   with no prompt, which looks broken.
2. **Revoke the tokens** ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)). Post the refresh token
   to the revocation endpoint so it stops working server-side. Do this so a stolen copy dies too.
3. **End the session at the AS** (RP-Initiated Logout). Send the user to the
   `end_session_endpoint` with your `id_token_hint` so the authorization server clears its own
   session cookie.

Do all three for a real logout. On shared devices, skipping step 3 is a genuine privacy problem.

---

## 14. Scopes, audiences, and claims

**Scopes** are what the *client* is allowed to ask for: `photos.read`, `photos.write`,
`invoices.read`. Coarse-grained, shown on the consent screen, so they should be human-readable —
the user has to understand what they're approving.

**Claims** are statements about the *user*: `email`, `name`, `sub`, `department`. Scopes act as the
request mechanism for claims (asking for `email` scope gets you the `email` claim).

**Audience** is which API a token is meant for. If your token is for `api.photos.example.com`, the
billing API should reject it even though it's a perfectly valid, unexpired, correctly-signed token.
[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource indicators let you request a token for a
specific audience.

**Scopes are not a permission system.** This is a common architectural mistake. A scope means *the
user let this app ask on their behalf*. It does not mean *this user is allowed to do this*. A token
with `invoices.write` doesn't mean this particular user may edit invoice #4172. Your API still has to
enforce its own authorization rules. Delegation and permission are different questions, and only
your application knows the answer to the second one.

Ask for the **minimum scopes you need, when you need them.** A first-run screen demanding every
permission depresses conversion; requesting incrementally, in context, works better and is easier to
justify to the user.

---

## 15. Doing this on Android

This project is an Android app, so here's how the above maps onto a device. The governing document is
[RFC 8252, *OAuth 2.0 for Native Apps*](https://www.rfc-editor.org/rfc/rfc8252).

### Use the system browser, never a WebView

This is RFC 8252's headline rule, and it's a hard one.

A `WebView` is controlled by your app. Your app can read everything typed into it — including the
user's password on the identity provider's own login page. That destroys the trust model: the entire
point of redirecting to the AS is that your app *doesn't* see the credentials. It also means:

- **No single sign-on.** A WebView has its own cookie jar, so the user logs in again in every app.
- **No password manager, no passkeys, no security keys**, and often broken 2FA.
- **Users can't verify the URL bar**, so they can't tell a real login page from a phishing one.
- **Providers block it.** Google, Microsoft, and others reject WebView-based auth outright.

Use **Custom Tabs** (`androidx.browser`) instead. It's the real browser, with the real cookie jar and
the real address bar, rendered inline in your app.

```kotlin
// Correct: the system browser via Custom Tabs, sharing cookies and credentials.
CustomTabsIntent.Builder()
    .build()
    .launchUrl(context, authorizationRequestUri)
```

### Redirect URIs

Two options for getting the code back into your app:

**Custom scheme** — `com.rick.oauthopenid://oauth2redirect`. Simple and universally supported. Use
your reverse-domain package name as the scheme, per RFC 8252. The weakness: another app can register
the same scheme, which is precisely why PKCE is mandatory here.

**App Links** — `https://app.example.com/oauth2redirect`, verified by hosting an
`assetlinks.json` on your domain. Stronger, because Android verifies the association and no other app
can claim it, but it requires a domain you control.

```xml
<activity android:name=".OAuthRedirectActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="com.rick.oauthopenid" android:host="oauth2redirect" />
    </intent-filter>
</activity>
```

### No client secret. Ever.

Your APK is a zip file. `apktool` and a text editor will find anything you embed. If a tutorial tells
you to paste a client secret into your Android app, that tutorial is wrong. Register the app as a
**public client** and rely on PKCE.

The same goes for `local.properties`-style config: keeping a secret out of *git* is not the same as
keeping it out of the shipped binary. It's still in the APK.

### Storing tokens

Tokens are credentials. Plain `SharedPreferences` is a world-readable-in-principle XML file, and
trivially readable on a rooted device or through a backup.

Note that `EncryptedSharedPreferences` (from `androidx.security:security-crypto`) is **deprecated**
and no longer the recommendation. The current approach is **DataStore** with encryption via
**Tink**, keyed by the **Android Keystore** so key material stays in hardware where available. For
high-value apps, gate token access behind a biometric prompt.

Also disable backup for token storage, or you'll ship credentials to the cloud:

```xml
<application android:dataExtractionRules="@xml/data_extraction_rules" ...>
```

### Libraries

**[AppAuth-Android](https://github.com/openid/AppAuth-Android)** (`net.openid:appauth`) is the
reference OIDC client for Android and implements RFC 8252 correctly. Be aware, though, that it is
effectively in maintenance limbo — the last release (0.11.1) was December 2021, it's still Java, and
it has a large backlog of open issues around newer Android versions. It still works and is still
widely deployed, but check its current state before committing to it. Alternatives worth evaluating
are your identity provider's own SDK (Auth0, Okta, Microsoft MSAL) or a newer Kotlin client.

For Google sign-in specifically, use **Credential Manager** with Sign in with Google, which is the
current platform API and handles passkeys too.

**Don't hand-roll the flow.** Not because it's conceptually hard — you've just read the whole thing —
but because the details that get skipped (constant-time comparisons, exact redirect matching, JWKS
caching and key rotation, `alg` allowlisting, clock skew, single-flight refresh) are exactly the ones
that turn into vulnerabilities. Understand it fully; then use a library.

### Seeing it run

The `app/` module in this repo does run the flow by hand, precisely so you can read it. Every step
from this document maps to a file:

| Concept | Code |
|---|---|
| [PKCE](#7-pkce--the-part-you-must-not-skip) | [`oauth/Pkce.kt`](app/src/main/java/com/rick/oauthopenid/oauth/Pkce.kt) |
| [Discovery, authorize URL, token exchange](#6-the-authorization-code-flow-step-by-step) | [`oauth/OidcClient.kt`](app/src/main/java/com/rick/oauthopenid/oauth/OidcClient.kt) |
| [ID token anatomy](#10-anatomy-of-an-id-token) | [`oauth/Jwt.kt`](app/src/main/java/com/rick/oauthopenid/oauth/Jwt.kt) |
| [The validation checklist](#10-anatomy-of-an-id-token) | [`oauth/IdTokenValidator.kt`](app/src/main/java/com/rick/oauthopenid/oauth/IdTokenValidator.kt) |
| Custom Tabs and the redirect | [`MainActivity.kt`](app/src/main/java/com/rick/oauthopenid/MainActivity.kt) |

It's preconfigured against a public demo provider, so it runs with no signup. See
[the README](README.md#the-demo-app) for how to start it.

---

## 16. Common mistakes

Roughly ordered by how often they show up in real code.

**Using OAuth for authentication.** Access token in, `/me` call, user logged in. Vulnerable to token
substitution. Use OIDC and validate the ID token. ([§3](#3-oauth-is-not-login--openid-connect-is))

**Not validating the ID token signature.** Decoding a JWT is not verifying it. An unverified JWT is
attacker-controlled JSON. ([§10](#10-anatomy-of-an-id-token))

**Not checking `aud` and `nonce`.** These are the two claims that make an ID token safe for login.
Without them you've rebuilt the vulnerability you adopted OIDC to avoid.

**Shipping a client secret in a mobile app or SPA.** It isn't secret. ([§15](#15-doing-this-on-android))

**Skipping PKCE**, or using `code_challenge_method=plain`. ([§7](#7-pkce--the-part-you-must-not-skip))

**Using a WebView for login.** Breaks SSO and password managers, exposes credentials, and is blocked
by major providers. ([§15](#15-doing-this-on-android))

**Using `email` as the user's primary key.** Use `(iss, sub)`. ([§10](#10-anatomy-of-an-id-token))

**Sending the ID token to APIs.** Wrong audience, wrong token, wrong layer. ([§4](#4-the-three-tokens))

**Trying to parse the access token in the client.** It's opaque to you by design.

**Wildcard or loose redirect URI matching.** Redirect URIs must match a registered value **exactly** —
no wildcards, no "starts with," no ignoring the port. Loose matching is a classic open-redirect
route to code theft.

**Access tokens in URLs.** They end up in server logs, browser history, and `Referer` headers. Use
the `Authorization` header.

**Not rotating or storing the new refresh token.** Silent logouts later.
([§13](#13-refresh-expiry-and-logout))

**Treating scopes as permissions.** Your API still owes its own authorization checks.
([§14](#14-scopes-audiences-and-claims))

**Long-lived access tokens** to avoid implementing refresh. This trades a small amount of work for a
large increase in blast radius.

**No `state` check** on the callback. ([§11](#11-state-vs-nonce-vs-code_verifier))

---

## 17. Glossary

| Term | Meaning |
|---|---|
| **Access token** | Credential for calling an API. Short-lived, scoped, opaque to the client. |
| **AS** | Authorization Server. Issues tokens, runs login and consent. |
| **`aud`** | Audience — who a token was minted for. |
| **Back channel** | Direct server-to-server HTTPS. Safe for tokens. |
| **Bearer token** | Whoever holds it can use it. No extra proof required — hence "protect it like a password." |
| **BCP** | Best Current Practice, a category of IETF document. |
| **Claim** | A single statement inside a token, e.g. `"email": "rick@example.com"`. |
| **Client** | The application requesting access. |
| **Confidential client** | A client that can keep a secret (server-side). |
| **Consent screen** | Where the user approves the requested scopes. |
| **DPoP** | Demonstrating Proof of Possession ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)). Binds a token to a key so a stolen token alone is useless. |
| **Discovery** | The `/.well-known/openid-configuration` metadata document. |
| **Front channel** | Data passed through the browser via redirects. Never send tokens here. |
| **ID token** | Signed JWT proving a user authenticated. For your app only. |
| **Introspection** | Asking the AS whether an opaque token is still valid. |
| **`iss`** | Issuer — who minted the token. |
| **JWT** | JSON Web Token. Base64URL-encoded, signed, readable by anyone. |
| **JWKS** | JSON Web Key Set — the AS's published public keys, at `jwks_uri`. |
| **`nonce`** | Random value binding an ID token to one specific request. |
| **OIDC** | OpenID Connect. Identity layer on top of OAuth 2.0. |
| **PAR** | Pushed Authorization Requests ([RFC 9126](https://www.rfc-editor.org/rfc/rfc9126)). Send the authorization request over the back channel first. |
| **PKCE** | Proof Key for Code Exchange. Stops stolen codes from being redeemed. |
| **Public client** | A client that cannot keep a secret (mobile, SPA, desktop). |
| **Refresh token** | Long-lived credential used only to get new access tokens. |
| **Resource owner** | The user who owns the data. |
| **RS** | Resource Server. The API that accepts access tokens. |
| **Scope** | A named permission the client requests. |
| **`state`** | Random value tying a callback to the request that started it. CSRF defense. |
| **`sub`** | Subject — the stable, unique user identifier. |

---

## 18. Spec map

Verified current as of September 2026.

### The essentials

| Spec | What it is |
|---|---|
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) | The OAuth 2.0 Authorization Framework — the core |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) | Bearer Token Usage — the `Authorization: Bearer` header |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) | PKCE |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | The identity layer |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | `/.well-known/openid-configuration` |

### Best current practice — read these

| Spec | What it is |
|---|---|
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) | **OAuth 2.0 Security BCP** (BCP 240, January 2025). The consolidated modern security guidance; updates RFCs 6749, 6750, and 6819. |
| [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) | **OAuth 2.0 for Native Apps** (BCP 212). The mobile rules — system browser, not WebView. |
| [RFC 10017](https://www.rfc-editor.org/rfc/rfc10017) | **OAuth 2.0 for Browser-Based Apps** (BCP 212, August 2026). SPA guidance; covers the BFF, token-mediating backend, and browser-client architectures. |

### OAuth 2.1

[draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) — **still an
Internet-Draft** (revision 16, September 2026; the working group's milestone is to submit it to the
IESG by December 2026). It is not an RFC yet.

OAuth 2.1 isn't a new protocol. It consolidates OAuth 2.0 + PKCE + the security BCP into one document
and deletes what proved unsafe:

- PKCE **required** for all authorization code flows, not just public clients
- **Implicit grant removed**
- **Password (ROPC) grant removed**
- **Exact** redirect URI string matching required
- Refresh tokens must be sender-constrained or rotated

You don't need to wait for the RFC. Following RFC 9700 today gets you essentially the same place.

### Common extensions

| Spec | What it is |
|---|---|
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | Authorization Server Metadata (discovery for plain OAuth) |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) | JSON Web Token (JWT) |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) | JWT profile for access tokens |
| [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) | Token Introspection |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) | Token Revocation |
| [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) | Device Authorization Grant |
| [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) | Token Exchange |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) | Resource Indicators (audience restriction) |
| [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) | Pushed Authorization Requests (PAR) |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) | DPoP — sender-constrained tokens |
| [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) | Rich Authorization Requests (fine-grained `authorization_details`) |
| [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) | mTLS client authentication and certificate-bound tokens |
| [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) | Dynamic Client Registration |

---

## Where to go next

- Re-read [§3](#3-oauth-is-not-login--openid-connect-is), [§5](#5-front-channel-vs-back-channel), and
  [§11](#11-state-vs-nonce-vs-code_verifier). Those three carry most of the conceptual weight.
- Skim [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700). It's 46 pages and it's the single highest
  value-per-page document in this whole list.
- Run a real flow against a live provider and watch it in a proxy. Seeing the actual redirects and
  the token response makes the whole thing click in a way reading can't.

Back to the [README](README.md).
