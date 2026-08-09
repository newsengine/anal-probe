# vibetesting-agent plugins (JSON templates)

Add your own black-box checks **without touching core code**. Drop `.json` template files in a
directory and vibetesting-agent's `plugins` category runs them Nuclei-style — but the format is plain **JSON**
(parsed with the built-in `JSON.parse`; there is **no YAML and no runtime dependency** — zero-dep is an
absolute rule).

## How it runs

```sh
# default directory: ./vibetesting-agent-plugins
vibetesting-agent https://example.com

# or point at any directory
vibetesting-agent https://example.com --plugins ./my-templates

# run ONLY the plugins category
vibetesting-agent https://example.com --only plugins --plugins ./plugins/examples
```

Each template describes **one** request and a set of matchers over the response. If the matchers match,
vibetesting-agent emits a **failing finding** with id `plugins.<your-template-id>`. If nothing matches, nothing
is emitted for that template. A single info finding `plugins.loaded` reports how many templates ran
(or `plugins.none` when the directory is absent/empty). A template that fails schema validation is
**skipped** (with an info finding naming the file) — a bad template can never break the scan.

Safety guarantees (enforced by the engine, not by trust):

- **GET/HEAD only** — any other method is rejected at validation time. Templates are non-destructive.
- One request per template; at most **100 templates** load from a directory.
- Requests are same-origin against the scanned host; response bodies are read with a hard byte cap and
  the scan's normal timeout.

## Schema

```jsonc
{
  "id": "x-powered-by",                 // required, unique-ish slug → finding id "plugins.x-powered-by"
  "title": "X-Powered-By discloses …",  // required, human-readable finding title
  "severity": "low",                    // required: "high" | "medium" | "low" | "info"

  "request": {
    "path": "/",                        // required, must start with "/"
    "method": "GET",                    // optional, "GET" (default) or "HEAD" only
    "headers": { "Accept": "*/*" }       // optional extra request headers
  },

  "matchers-condition": "and",          // optional: "and" (default) | "or" — how matchers combine
  "matchers": [                          // required, non-empty array; each is one of:

    // status: response code equals one of these
    { "type": "status", "status": 200 },
    { "type": "status", "status": [200, 204, 301] },

    // header: inspect a response header (case-insensitive name)
    //   - with no constraint  → matches when the header is present
    //   - regex / contains / equals → all provided constraints must hold on its value
    //   - "negative": true    → invert (e.g. header is ABSENT)
    { "type": "header", "name": "x-powered-by", "regex": ".+" },
    { "type": "header", "name": "content-type", "contains": "json" },
    { "type": "header", "name": "cross-origin-opener-policy", "negative": true },

    // body-regex: JS regexp source over the response body ("flags" optional; g/y stripped)
    { "type": "body-regex", "regex": "DEBUG\\s*=\\s*true", "flags": "i" },

    // body-contains: case-sensitive substring of the response body
    { "type": "body-contains", "contains": "phpinfo()" }
  ],

  "fix": "One-line remediation shown to the user.",  // optional
  "owasp": "A05",                        // optional, echoed into the finding detail
  "cwe": ["CWE-200"]                     // optional, echoed into the finding detail
}
```

### Matcher reference

| type            | required fields | optional fields             | matches when |
|-----------------|-----------------|-----------------------------|--------------|
| `status`        | `status` (number or number[]) | —             | response status is (in) `status` |
| `header`        | `name`          | `regex`, `contains`, `equals`, `flags`, `negative` | header present and every given constraint holds |
| `body-regex`    | `regex`         | `flags`, `negative`         | regex tests true against the body |
| `body-contains` | `contains`      | `negative`                  | body includes the substring |

Any matcher may set `"negative": true` to invert its result. The whole template matches when
`matchers-condition` (`and`/`or`) over all matcher results is satisfied.

## Full annotated example

Detect a publicly reachable `phpinfo()` page (see `examples/exposed-phpinfo.json`):

```json
{
  "id": "exposed-phpinfo",
  "title": "phpinfo() page is publicly reachable",
  "severity": "high",
  "request": { "path": "/phpinfo.php", "method": "GET" },
  "matchers-condition": "and",
  "matchers": [
    { "type": "status", "status": 200 },
    { "type": "body-contains", "contains": "phpinfo()" }
  ],
  "fix": "Delete phpinfo.php from the production docroot.",
  "owasp": "A05",
  "cwe": ["CWE-200"]
}
```

See the other files in [`examples/`](./examples) for a header-disclosure check and a
missing-security-header (negative matcher) check.
