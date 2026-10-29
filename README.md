# cache-key-lint

[![tests](https://github.com/Young-Syre/cache-key-lint/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/cache-key-lint/actions/workflows/tests.yml)
[![Node](https://img.shields.io/badge/node-%3E%3D20-blue.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](package.json)

**Infer a web cache's key from local HTTP captures, then report what the key leaves out and what it wrongly includes. Offline: the tool never sends a request.**

---

## The key is never the whole request

A cache stores a response under a *key*, and the key is almost never the whole request.

That is not a bug, it is the point. A cache that keyed on every byte of every request would never get a second hit. So a CDN keys on, roughly, the host, the path, some of the query, and whatever the origin named in `Vary` — and it discards the rest. The origin, meanwhile, reads whatever it likes: an `X-Forwarded-Host` to build an absolute URL, a cookie to pick a locale, a `;`-separated parameter its framework happens to parse.

Every one of those discarded-but-read inputs is a cache-poisoning vector. The attacker sends one request that the origin answers differently; the cache files that answer under the key everyone else uses; every later visitor is served the attacker's version.

The mirror image is cache deception. Here the attacker changes the URL rather than a header, so that the two pieces of software disagree about *which resource it names*. The cache sees `/account.css`, matches its static-file rule and stores the response for ten minutes. The origin sees a route that ignores a trailing extension and serves the signed-in account page. Now any URL the attacker chooses will return someone else's account page out of a public cache.

Both halves reduce to the same thing: **two parsers, one URL, and a disagreement about what identifies a resource.** A CDN and an origin. A router and a static-file handler. A reverse proxy and the application behind it.

Testers usually find these by hand — guess a header name, append `.css`, look for a reflection. That works, and it is also unsystematic: you find the vector you thought of. The systematic version is to model the key from evidence and then diff that model against what actually varied. That is what this tool does, from capture data you already have, without touching the target.

> ### Cache-buster discipline
>
> Resolving a key means sending requests, and a probe without a cache-buster is not a test — it is a modification of a cache that sits in front of other people's traffic. If the input turns out to be unkeyed, your payload is stored under the key real users request, and they receive it until the entry expires or someone purges it. That is a production incident caused by the test rather than by the bug.
>
> The `plan` subcommand exists so you do not have to remember this: it emits the request matrix with a unique cache-buster already on every probe. [Full discipline notes below.](#plan--the-request-matrix)

## What it reads

Local capture data only. Two formats:

- **HAR 1.2** — anything a browser's network panel or an intercepting proxy exports. `log.entries[].request` / `.response`, with headers as the usual `name`/`value` array, bodies from `postData.text` and `content.text`, and base64 content decoded. HAR's separate `cookies` arrays are folded into `Cookie` / `Set-Cookie` when the header itself is missing.
- **A small native format**, for captures you write by hand or generate:

```json
{
  "label": "my-capture",
  "entries": [
    {
      "request": {
        "method": "GET",
        "url": "https://app.example/account",
        "headers": { "Cookie": "session=FIXTURE-USER-A" },
        "body": null
      },
      "response": {
        "status": 200,
        "headers": { "Cache-Control": "public, max-age=600", "CF-Cache-Status": "HIT" },
        "body": "<html>…</html>"
      }
    }
  ]
}
```

Headers may be an object, a `{name, value}` array, or an array of pairs. Several capture files can be passed at once and are analysed as one body of evidence.

Captures are treated as untrusted input. Nothing in them is evaluated, no URL in them is fetched, and a malformed entry is skipped with a warning rather than aborting the run.

**The useful capture shape is the same resource requested several ways** — once plainly, once with one header added, once with a cookie changed, once with `.css` appended. The tool's attribution rules only fire on pairs that differ in exactly one request component, because a pair that differs in two proves nothing about either.

## Install

```bash
npm install -g cache-key-lint     # once published
# or, from a clone:
npm install && npm run build
node dist/src/cli.js --help
```

Node 20 or newer. **No runtime dependencies** — TypeScript and `@types/node` are build-time only, and a test asserts the `dependencies` field stays absent.

## Usage

```bash
cache-key-lint capture.har                          # lint; text report
cache-key-lint a.har b.json --format markdown       # several captures, one report
cache-key-lint capture.har --format json            # for a pipeline
cache-key-lint plan capture.har --url https://app.example/account
cache-key-lint rules            # the rule catalogue
cache-key-lint delimiters       # the path-delimiter matrix
cache-key-lint cache-headers    # the cache-status headers read as evidence
cache-key-lint normalisers      # the body normalisers applied before any diff
```

### A capture that is configured correctly

```
cache-key-lint 0.1.0 — 5 entries from clean-well-configured
Credential values are redacted.

INFERRED CACHE KEYS
  www.example/  [GET; 2 observations; key confidence 0.75]
    in the key:
      host — assumed: every cache in common use keys on the request host
      path — assumed: every cache in common use keys on the request path
      header:accept-encoding — the origin declares Vary: accept-encoding, which a conformant
        cache must include in the key
    untested by this capture:
      method — only one method was observed, so the method’s place in the key is untested
      header:x-forwarded-host — changing header:x-forwarded-host did not change the
        response, so the capture cannot place it on either side of the key
    confidence from: base 0.30; a Vary header was present (+0.10); a cache-status header
      was present on at least one observation (+0.25); 1 single-variable pair attributed
      (+0.10)

  www.example/account  [GET; 2 observations; key confidence 0.75]
    in the key:
      host — assumed: every cache in common use keys on the request host
      path — assumed: every cache in common use keys on the request path
      header:cookie — the origin declares Vary: cookie, which a conformant cache must
        include in the key
    not in the key:
      cookie:session — the response varied with cookie:session and no Vary names it —
        inferred, not proven: the capture shows the origin reading it, not the cache ignoring
        it
    untested by this capture:
      method — only one method was observed, so the method’s place in the key is untested
    confidence from: base 0.30; a Vary header was present (+0.10); a cache-status header
      was present on at least one observation (+0.25); 1 single-variable pair attributed
      (+0.10)

  www.example/assets/app.1f3a9c2b4d5e6f70.js  [GET; 1 observation; key confidence 0.65]
    in the key:
      host — assumed: every cache in common use keys on the request host
      path — assumed: every cache in common use keys on the request path
      header:accept-encoding — the origin declares Vary: accept-encoding, which a conformant
        cache must include in the key
    untested by this capture:
      method — only one method was observed, so the method’s place in the key is untested
    confidence from: base 0.30; a Vary header was present (+0.10); a cache-status header
      was present on at least one observation (+0.25)

CACHE HEADER EVIDENCE
  entry 3  X-Cache: MISS
    GET https://www.example/
    Varnish, CloudFront, Fastly and others — reported by the serving cache; not a hit
  entry 4  X-Cache: MISS
    GET https://www.example/
    Varnish, CloudFront, Fastly and others — reported by the serving cache; not a hit
  entry 1  X-Cache: MISS
    GET https://www.example/account
    Varnish, CloudFront, Fastly and others — reported by the serving cache; not a hit
  entry 2  X-Cache: MISS
    GET https://www.example/account
    Varnish, CloudFront, Fastly and others — reported by the serving cache; not a hit
  entry 5  X-Cache: HIT
    GET https://www.example/assets/app.1f3a9c2b4d5e6f70.js
    Varnish, CloudFront, Fastly and others — served from store
  entry 5  Age: 86400
    GET https://www.example/assets/app.1f3a9c2b4d5e6f70.js
    any RFC 9111 shared cache — served from store

FINDINGS (0)
  none

SUMMARY  critical 0  high 0  medium 0  low 0  info 0  |  proofs 0, inferences 0
Body normalisers applied before comparison: csp-nonce, csrf-meta, csrf-token, iso-timestamp,
http-date, epoch-millis, epoch-seconds, uuid, build-hash-path, build-hash-filename,
cache-buster-query, request-id, etag-literal, whitespace
```

Three resources, no findings, exit code 0. The private resource is `no-store` and declares `Vary: Cookie`; the public page ignores `X-Forwarded-Host`; the only thing a shared cache is holding is a content-addressed asset. Note what the report still says about the key: `x-forwarded-host` is reported as **untested**, not as absent from the key, because two identical responses do not prove the cache ignores a header.

### A capture that is not

`examples/css-suffix-deception.har` is the deception case: an authenticated account page, the same page at `/account.css` with a Cloudflare `HIT` on it, the same page reached by escaping `/static/`, and the same page reached through a `;` path parameter.

```
FINDINGS (12)

  [critical] CKL-E001 (proof) — Cache reported a HIT on a response that should not be stored
    resource: GET https://app.example/account.css
    entries:  2
    CF-Cache-Status: HIT — the serving cache (Cloudflare) reports this response came from its
    store, and the response identifies a user. the request that produced it carried the session
    cookie session; the body contains an e-mail address; the body contains a personal greeting
    ("Signed in as", "Welcome back", "Hello,"); the body contains a sign-out control, which only
    an authenticated page carries.
      - cache status: CF-Cache-Status: HIT (Cloudflare)
      - session-cookie-gated: the request that produced it carried the session cookie session
        [inference]
      - body-marker:email-address: the body contains an e-mail address [inference]
      - body-marker:greeting: the body contains a personal greeting ("Signed in as", "Welcome
        back", "Hello,") [inference]
      - body-marker:logout-control: the body contains a sign-out control, which only an
        authenticated page carries [inference]
      - directives: public permits shared storage
      - why this outranks everything else in the report: the other rules argue from what the
        origin did and what the directives permit; this one is the cache stating that the
        response was stored and reused
      - caveat: the identity signals here are heuristic, so confirm the stored body is genuinely
        another user’s before reporting it as such

  [critical] CKL-D004 (inference 0.60) — Cacheable response on a user-specific resource
    resource: GET https://app.example/account;ckl.js
    entries:  4
    This response identifies a user and a shared cache is permitted to store it (public permits
    shared storage). What identified the user: the request that produced it carried the session
    cookie session; the body contains an e-mail address; the body contains a personal greeting
    ("Signed in as", "Welcome back", "Hello,"); the body contains a sign-out control, which only
    an authenticated page carries.
      - session-cookie-gated: the request that produced it carried the session cookie session
        [inference]
      - body-marker:email-address: the body contains an e-mail address [inference]
      - body-marker:greeting: the body contains a personal greeting ("Signed in as", "Welcome
        back", "Hello,") [inference]
      - body-marker:logout-control: the body contains a sign-out control, which only an
        authenticated page carries [inference]
      - storability: public permits shared storage

  …
```

The full run prints 12 findings — 4 critical, 5 high, 2 medium, 1 low; 9 proofs and 3 inferences — and exits 1.

## The inferred cache key

This is the tool's main output, and the findings hang off it. For every distinct resource in the capture it reports which request components the evidence places **in** the key, which it places **outside** the key, and which the capture simply did not test — each with the evidence that put it there.

```
  app.example/account  [GET; 1 observation; key confidence 0.65]
    in the key:
      host — assumed: every cache in common use keys on the request host
      path — assumed: every cache in common use keys on the request path
      header:cookie — the origin declares Vary: cookie, which a conformant cache must
        include in the key
    untested by this capture:
      method — only one method was observed, so the method’s place in the key is untested
    confidence from: base 0.30; a Vary header was present (+0.10); a cache-status header
      was present on at least one observation (+0.25)
```

**A cache key is private to the cache.** Nothing outside the cache can read it, so almost everything in this section is deduction, and the report is explicit about which kind:

- `host` and `path` are flagged as *assumptions*, not observations.
- A `Vary` token goes **in** the key because a conformant cache must put it there — that is the origin's own statement.
- A component the response varied with, absent from `Vary`, goes **outside** the key as an *inference*: the capture shows the origin reading it, not the cache ignoring it.
- A component that changed nothing goes to **untested**. This is the distinction that most hand-written notes lose.
- The one genuinely strong signal is a cache hit: when changing a component produced an equivalent body served from the store, the two requests demonstrably shared one key, and the evidence line says so.

### The confidence figure

Mechanical, so you can judge it rather than trust it:

| term | value |
| --- | --- |
| base | 0.30 |
| a cache-status header was present on at least one observation of this resource | +0.25 |
| each single-variable pair the tool could attribute | +0.10, capped at +0.30 |
| a `Vary` header was present | +0.10 |
| any pair differed in more than one request component | −0.10 |

Clamped to the range 0.10–0.95. It never reaches 1, because a key is never observable. The `confidence from:` line in every report itemises which terms applied.

## Rules

| ID | name | severity | default kind | mechanism |
| --- | --- | --- | --- | --- |
| `CKL-U001` | Response varies with a request header absent from Vary | high | inference | The header reaches the origin and changes the response, but nothing tells the cache to include it in the key, so one request stores a response that every later request receives. |
| `CKL-U002` | Routing header reflected into the response | high | proof | Frameworks build absolute URLs from X-Forwarded-* and Forwarded rather than from the Host they were keyed on, so an attacker-supplied host lands in a script src, a Location or a canonical link. |
| `CKL-U003` | Response varies with a query parameter the cache may exclude | high | inference | Caches are routinely configured to ignore query parameters, or to key on an allow-list of them, while the origin branches on every one it receives. |
| `CKL-U004` | Cache and origin disagree on query normalisation | medium | inference | Parameter order, duplicate names, name case, `;` separators and empty parameters are each normalised differently by caches and origins, so two spellings of one query can be one key and two responses. |
| `CKL-U005` | Response varies with a cookie while Vary: Cookie is absent | high | inference | Cookies are per-user by construction and are almost never in a CDN key, so a response that depends on one is a response served to the wrong user. |
| `CKL-U006` | Vary: * on a cacheable response | low | proof | Vary: * means no request can ever match a stored response, so either the caching is pointless or an intermediary is ignoring the header — and which of the two is true is unknowable from the response alone. |
| `CKL-U007` | Vary names a header the origin does not read | low | inference | A Vary token that does not affect the response fragments the cache for no benefit, and hides the fact that the header which does affect it is missing from the list. |
| `CKL-U008` | Vary: User-Agent | low | proof | User-Agent has effectively unbounded cardinality, so caches normalise or drop it; relying on it to separate responses means relying on behaviour the cache does not promise. |
| `CKL-U009` | HEAD or Range response may be stored under a key a GET would hit | medium | inference | The request method and the Range header are part of the request but not always part of the key, so a bodyless or partial response can be returned for a full GET. |
| `CKL-U010` | Fat GET: a request body changes a GET response | high | proof | No cache keys on a GET request body, so if the origin reads one it is reading an input that is completely invisible to the key. |
| `CKL-D001` | Static extension suffix resolves to a dynamic resource | high | inference | The cache decides what is static from the path suffix while the origin decides what to serve from its router, and routers commonly ignore a trailing extension. |
| `CKL-D002` | Origin tolerates a path delimiter the cache keys on | medium | proof | Each delimiter is a byte sequence one parser treats as ending the resource name and the other treats as part of it; that asymmetry is what makes a suffix reachable. |
| `CKL-D003` | Static-prefix escape via path normalisation | high | inference | A cache rule that matches /static/ on the raw path can be satisfied by a path the origin percent-decodes and resolves back out of that directory. |
| `CKL-D004` | Cacheable response on a user-specific resource | critical | inference | Caching is per-resource and authentication is per-user, so a response that identifies a user and is storable by a shared cache will be handed to whoever asks next. |
| `CKL-D005` | Cache and origin disagree on path normalisation | medium | inference | Two spellings of one path are two keys to a cache that compares bytes and one resource to an origin that normalises first, which both splits the cache and creates a key an attacker can choose. |
| `CKL-C001` | private combined with a positive max-age | medium | proof | private restricts storage to one user and max-age invites storage; an intermediary that honours only the freshness half stores a private response. |
| `CKL-C002` | no-cache without no-store on an authenticated response | medium | proof | no-cache permits storing the response and only requires revalidation before reuse, so the body sits in a shared cache and a failed or skipped revalidation serves it. |
| `CKL-C003` | s-maxage overrides a restrictive max-age | high | proof | s-maxage applies to shared caches and takes precedence there, so a carefully chosen max-age=0 protects browsers while the CDN keeps the response for as long as s-maxage says. |
| `CKL-C004` | Revalidation requested without must-revalidate | low | proof | Without must-revalidate (or proxy-revalidate) a cache is permitted to serve a stale stored response when the origin cannot be reached, which is exactly when stale data is most harmful. |
| `CKL-C005` | stale-while-revalidate or stale-if-error extends the exposure window | medium | proof | Both extensions license serving a stored response after it has expired, so a poisoned or private entry outlives its max-age by the stale window. |
| `CKL-C006` | Pragma: no-cache relied on alone | medium | proof | Pragma is an HTTP/1.0 request-header compatibility feature; as a response header it has no defined effect, so a response carrying only Pragma is uncontrolled. |
| `CKL-C007` | No Cache-Control on a heuristically cacheable response | medium | proof | RFC 9111 lets a cache store and reuse a response with no explicit freshness information by guessing one, so silence is not the same as "do not cache". |
| `CKL-E001` | Cache reported a HIT on a response that should not be stored | critical | proof | A hit status from the serving cache is the one piece of evidence that settles the argument: the response was stored, and it was reused. |
| `CKL-E002` | Nonzero Age on a response carrying a user identifier | high | proof | Age is the time a shared cache has held the response, so any positive value on a per-user response means the response is already in a shared store. |

Reproduce this table with `cache-key-lint rules --format markdown`.

Each finding is labelled `proof` or `inference`. A proof carries confidence 1 and is something the capture shows directly — a value reflected into a body, a `HIT` header, a directive contradiction, two bodies that differ. An inference carries a confidence below 1 and always says, in its evidence, why it is an inference and what would settle it. **A test asserts this**: no proof may carry a confidence other than 1, and no inference may omit its reason.

## Cache-header evidence

A cache-status header is the only thing in a capture that reports on the *cache's* behaviour rather than the origin's, so `CKL-E001` — a hit on a response that identifies a user — is the strongest finding the tool can produce. These headers are treated purely as capture evidence: the tool repeats what the serving cache said and does not model any vendor's key algorithm.

| header | reported by | values read as a hit |
| --- | --- | --- |
| `CF-Cache-Status` | Cloudflare | `hit`, `stale`, `updating`, `revalidated` |
| `X-Cache` | Varnish, CloudFront, Fastly and others | `hit` |
| `X-Cache-Hits` | Varnish / Fastly (hit counter) | any value greater than zero |
| `X-Vercel-Cache` | Vercel | `hit`, `stale` |
| `X-Served-By` | Fastly (serving node) | none — reported as context only |
| `Fastly-Debug-Digest` | Fastly (hashed key material) | none — reported as context only |
| `X-Drupal-Cache` | Drupal page cache | `hit` |
| `X-Proxy-Cache` | nginx proxy_cache | `hit` |
| `CDN-Cache-Control` | CDN-targeted directive (RFC 9213) | none — reported as context only |
| `Surrogate-Control` | Fastly / Squid surrogate directive | none — reported as context only |
| `Surrogate-Key` | Fastly purge tagging | none — reported as context only |
| `Age` | any RFC 9111 shared cache | any value greater than zero |

Reproduce with `cache-key-lint cache-headers --format markdown`. Every cache-status header in a capture is listed in the report's evidence table whether it was a hit or not, so a reader can see what the capture did and did not establish.

## The delimiter matrix

Cache deception needs a byte sequence that one parser treats as ending the resource name and the other treats as part of it. There are not many, and they are all known:

| delimiter | name | what has to be true at the origin |
| --- | --- | --- |
| `.` | dot (extension suffix) | route matches a prefix, or the framework strips a trailing extension / format suffix |
| `/` | trailing slash segment | router tolerates an extra path segment and ignores it, e.g. a greedy or optional route parameter |
| `%2F` | encoded slash | origin decodes %2F before routing while the cache keys on the raw bytes |
| `//` | doubled slash | origin collapses empty path segments; the cache does not, so the two see different paths |
| `;` | path parameter (matrix parameter) | Java/Spring-style path parameters, and some proxies, discard everything after `;` |
| `%3B` | encoded semicolon | as above, but reached after the origin percent-decodes |
| `?` | query start | the cache has been configured to key on the full URL including query, or to ignore it entirely |
| `%23` | encoded hash | origin decodes %23 to `#` and truncates the path there; the cache keeps the encoded bytes |
| `..%2f` | encoded dot-segment | origin decodes then resolves `..`, escaping a static prefix the cache matched on |

Reproduce with `cache-key-lint delimiters --format markdown`.

`CKL-D002` reports which of these the capture shows the origin tolerating — a 2xx at `base + delimiter + suffix` where `base` is a resource the capture also contains — and names the ones it has *not* shown, so the gap is visible. `plan` emits a probe for every delimiter against both `.css` and `.js`.

## Body normalisation

Two responses to the same URL almost never match byte for byte. CSP nonces, CSRF tokens, request ids, timestamps and build hashes rotate on every response, and a diff that reports those as "the response varied" buries the one difference that matters. So bodies are normalised before any comparison:

| normaliser | what it masks |
| --- | --- |
| `csp-nonce` | nonce-<value> inside a Content-Security-Policy or a nonce= attribute |
| `csrf-meta` | csrf/xsrf token carried in a meta tag attribute or a hidden form input |
| `csrf-token` | csrf/xsrf/authenticity token in an attribute, JSON field or meta tag |
| `iso-timestamp` | ISO 8601 date-time, with or without fractional seconds and zone |
| `http-date` | RFC 9110 IMF-fixdate, as it appears in bodies that echo Date |
| `epoch-millis` | 13-digit epoch milliseconds |
| `epoch-seconds` | 10-digit epoch seconds |
| `uuid` | RFC 9562 UUID in any version |
| `build-hash-path` | content-hash segment in a bundler asset path (/_next/static/<hash>/, /assets/<hash>/) |
| `build-hash-filename` | content hash inside an asset filename (app.1f3a9c2b.js, main-9f8e7d6c.css) |
| `cache-buster-query` | cache-buster or version query parameter on an asset reference |
| `request-id` | request/trace/correlation id echoed into the body |
| `etag-literal` | quoted entity tag echoed into the body |
| `whitespace` | runs of whitespace collapsed to one space, and leading/trailing trimmed |

Reproduce with `cache-key-lint normalisers --format markdown`. Every applied normaliser is listed at the foot of each report.

The set is configurable. `--normalisers <file>` adds your own, `--no-default-normalisers` drops these, and the file format is deliberately narrow:

```json
{
  "normalisers": [
    { "id": "order-no", "description": "order numbers", "pattern": "ORD-\\d+", "flags": "gi" }
  ]
}
```

`examples/nonce-noise.json` exists for this: two observations of one URL whose responses differ only in a nonce, a CSRF token, a timestamp, a build hash and a request id. It must report nothing, and both the test suite and CI assert that it does.

## `plan` — the request matrix

Linting a capture tells you what the capture already shows. Resolving the key means sending requests. `plan` emits the matrix to send:

```
cache-key-lint 0.1.0 — request matrix for https://app.example/account

!! CACHE-BUSTER DISCIPLINE — READ BEFORE SENDING ANYTHING
   Every probe below carries a unique cache-buster parameter. Keep it.
   A probe sent without one is not a test: if the input turns out to be unkeyed, the response
   is stored under the key real users request, and every one of them receives your payload
   until the entry expires or the cache is purged. That is a production incident caused by
   the test, not by the bug.
   Send each probe twice — once to store, once to confirm the stored copy comes back — and
   confirm with the cache-status header, not with the body alone.
   Change one thing per probe. A probe that differs in two components tells you nothing about
   either.
   When a probe does poison its own buster key, note the key and the expiry, and say so in
   the report: the reviewer needs to know what was left behind.
   Scope and authorisation come first. A cache sits in front of other people’s traffic, so
   the blast radius of a mistake here is not limited to your own account.

FROM THE CAPTURE
   1 observation of this resource in the capture; inferred key confidence 0.65.
   Evidence already places in the key: host, path, header:cookie.
   Untested in the capture: method.

PROBES (52)  buster: cklcb=cklNNN, unique per probe

-- baseline --

  001  GET https://app.example/account?cklcb=ckl001
       why: Establish that the cache-buster parameter produces a key of its own.
       look for: first request a miss, second request a hit on the same buster value. If the
       second is also a miss the resource is not cached at all and nothing below will tell
       you anything; if the first is a hit the buster is being stripped and you need a

  …
```

52 probes for this target, in six groups: a baseline that proves the cache-buster works, one probe per routing header (plus a control header the origin should not read), every delimiter against `.css` and `.js`, the six query-spelling permutations plus a buster-only probe, a cookie probe, a HEAD/Range pair, and a fat GET. Every probe states what to look for, and every probe carries a unique cache-buster.

**The cache-buster discipline is not optional.** It is reproduced at the top of every `plan` output because the failure mode is not a bad finding, it is a production outage you caused. The matrix is a list of requests to send against a target you are authorised to test; a cache sits in front of other people's traffic, so the blast radius of a mistake is not limited to your own account. If a probe does poison its own buster key, note the key and its expiry and say so in the report — the reviewer needs to know what you left behind.

## Redaction

A capture of an authenticated session is a credential store, and reports get pasted into tickets. By default every credential value is removed from every output format, while the **names** are kept, because "the response varies with the cookie `session`" is the finding and the cookie's value is not.

- `Cookie: session=…; theme=…` is printed as `session=<redacted>; theme=<redacted>`.
- `Authorization: Bearer …` keeps its scheme: `Bearer <redacted>`.
- `Set-Cookie` keeps its name and its attributes.
- Every credential value found anywhere in the loaded captures is then stripped
  from all output as a literal, which is what makes the guarantee hold when a
  token has been echoed into a body or a URL. "Anywhere" includes the query
  *and fragment* of a URL carried in a `Referer`, `Location` or
  `Content-Location` header — those headers are kept because they affect
  routing and caching, and an OAuth implicit-flow redirect puts
  `access_token` after the `#` of exactly such a `Location`.

`--no-redact` prints values verbatim and says so in the report header. A test asserts that no fixture credential appears in the text, JSON or markdown output of every shipped example by default, and CI asserts the same against the built CLI.

## What this tool does not do

- **It does not send requests.** No fetch, no DNS, no probing — a test fails the build if anything in `src/` imports a networking module or references `fetch`, `eval` or a dynamic import. Only `node:fs` and `node:path` are imported from the standard library. The consequence is that it cannot confirm anything; `plan` exists because confirmation needs a network and a decision you should make deliberately.
- **It cannot read a cache key.** Keys are private to the cache. Everything the key section places outside the key, other than components settled by an observed hit, is an inference with a stated confidence.
- **It does not model any specific CDN.** `storability()` is a deliberately simplified reading of RFC 9111 §3 and §5.2, chosen so that every verdict can be explained in one line. Real CDNs are more permissive than the RFC in places and more conservative in others. Where a capture carries a vendor cache-status header, that observation is reported alongside the model and always outranks it.
- **Path normalisation is modelled, not known.** `originCandidates()` applies a documented set of transformations — percent-decode, collapse slashes, resolve dot segments, strip path parameters, truncate at a decoded hash, strip a static extension, strip a trailing slash — to produce the paths an origin *might* resolve a URL to. When the capture also contains the resource at the resolved path and the bodies match once normalised, the finding becomes a proof. Otherwise it stays an inference.
- **Identity detection is partly heuristic.** `Set-Cookie`, an `Authorization`-gated request, `Vary: Cookie`, and two credentials producing two bodies are treated as proof that a response is per-user. An e-mail address, a personal greeting, a user-id field or a sign-out link in the body are heuristics, reported as inferences and marked `[inference]` in the evidence. `CKL-D004` requires either one proof-strength signal or two heuristic ones before it will fire.
- **It will not find a vector the capture does not contain.** Nothing here guesses at headers the capture never carried. That is `plan`'s job.
- **One capture, one point in time.** Cache configuration changes, and a `MISS` in a capture says nothing about whether the resource is cacheable at a different edge or an hour later.
- **No HAR 1.2 field beyond request and response is read.** Timings, page records, `_resourceType` and WebSocket frames are ignored.

## Exit codes

| code | meaning |
| --- | --- |
| `0` | analysis completed and no finding reached `--fail-on` |
| `1` | analysis completed and at least one finding reached `--fail-on` (default threshold: `medium`) |
| `2` | usage error, or a capture that could not be read or parsed |
| `3` | an unexpected internal error |

`--fail-on never` always exits 0. `plan`, `rules`, `delimiters`, `cache-headers` and `normalisers` exit 0 unless the arguments were wrong.

## Examples

Every capture in `examples/` is **fabricated**. The hostnames are `.example` and `.invalid`, the session values are obviously synthetic, and none of them was taken from a real deployment.

| file | what it demonstrates | findings |
| --- | --- | --- |
| `unkeyed-x-forwarded-host.json` | `X-Forwarded-Host` and `Forwarded` reflected into a script src, a canonical link and a `Location` | 4 |
| `css-suffix-deception.har` | `.css` suffix, `;` path parameter and `/static/` escape all reaching an authenticated page, with a Cloudflare `HIT` on it | 12 |
| `clean-well-configured.json` | a correctly configured deployment | 0 |
| `nonce-noise.json` | two responses differing only in per-response noise | 0 |
| `unkeyed-query-cookie-and-directives.json` | query, cookie, method, `Range`, fat-GET and every `Cache-Control` rule | 21 |

Between them they exercise all 24 rules; a test asserts that no catalogued rule is without a worked example.

## Development

```bash
npm install
npm run typecheck     # tsc --noEmit, strict
npm run build
npm test              # build, then node --test over dist/test
```

`tsconfig.json` is strict, including `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes` and `noUnusedLocals`. The test suite is 218 cases (520 assertion calls) run with `node --test`; it covers every rule, the body-normalisation logic, the redaction guarantee, the capture parsers, the key model, the request matrix, the CLI exit codes and the no-network property.

## Licence

MIT. See [LICENSE](LICENSE).
