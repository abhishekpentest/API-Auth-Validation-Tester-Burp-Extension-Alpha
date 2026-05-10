# API Auth & Validation Tester

API Auth & Validation Tester is a Burp Suite extension built in Java with the Montoya API. It helps security testers quickly triage API authentication enforcement, input validation behavior, length handling, and unexpected-parameter handling while crawling an application through Burp.

This extension is purely intended to reduce repetitive manual work for penetration testers. It automates common first-pass API checks so testers can spend more time reviewing meaningful evidence, validating business logic, and confirming impact manually.

The extension is intended for authorized security testing. It performs active HTTP requests against captured API traffic, so use it only on applications you own or have explicit permission to test.

## Features

- Captures API-like requests from Burp Proxy history and/or live Proxy traffic.
- Tests authentication enforcement by removing a configurable auth header.
- Tests query parameters, JSON fields, form fields, and selected headers with special characters.
- Tests length validation with long payloads.
- Tests unexpected parameter handling by injecting `test=test`.
- Tracks refresh-token endpoints and applies the latest live access token to non-authentication tests.
- Supports safe-method-only testing by default.
- Exports a Markdown report grouped by endpoint.
- Includes full request and response evidence for each recorded result.

## Requirements

- Burp Suite with Montoya API support.
- Java 21 or lower.
- Gradle, or the included lightweight `gradlew` / `gradlew.bat` bootstrap scripts.

Burp currently supports Java extensions up to Java 21, so this project targets Java 21.

## Download / Use Directly

If you only want to use the extension, download the prebuilt JAR from this repository:

```text
build/libs/api-auth-validation-tester-0.1.0.jar
```

Then load it in Burp Suite:

1. Open Burp Suite.
2. Go to **Extensions > Installed**.
3. Click **Add**.
4. Set **Extension type** to **Java**.
5. Select the downloaded JAR:

```text
api-auth-validation-tester-0.1.0.jar
```

6. Open the **API Auth & Validation Tester** tab.

## Build From Source

From the project root:

```bash
./gradlew build
```

On Windows:

```powershell
.\gradlew.bat build
```

The generated JAR will be created at:

```text
build/libs/api-auth-validation-tester-0.1.0.jar
```

## Load Built JAR In Burp Suite

1. Open Burp Suite.
2. Go to **Extensions > Installed**.
3. Click **Add**.
4. Set **Extension type** to **Java**.
5. Select the generated JAR:

```text
build/libs/api-auth-validation-tester-0.1.0.jar
```

6. Open the **API Auth & Validation Tester** tab.

## Basic Usage

1. Configure the target domain or enable **Use Burp Suite scope instead of domain text**.
2. Configure the auth header name, such as `Authorization` or `X-Auth-Token`.
3. Choose which tests to run.
4. Choose the request source mode.
5. Click **Start Scan**.
6. Crawl the application through Burp, or let the extension process existing Proxy history depending on the selected mode.
7. Review live results in the table.
8. Click **Export Markdown Report** when finished.

## Request Source Modes

The extension supports three request source modes.

### Existing Proxy History Only

Tests matching API requests that were already present in Burp Proxy history before **Start Scan** was clicked.

This mode is useful when you have already crawled the application and want to test the captured traffic afterward.

### New Traffic After Start Only

Ignores old Proxy history and tests matching API requests captured after **Start Scan** is clicked.

If an API existed in old Proxy history and you hit it again after starting the scan, it will still be tested. This is useful when you want the extension to test requests using the current active session/token.

### Existing History And New Traffic

Tests matching API requests already in Proxy history and continues watching for new matching traffic.

This mode is useful for a broad scan where you want to cover both previously captured and newly discovered endpoints.

## Scope And Filtering

The extension only tests requests that pass its filters:

- The request must match the configured target domain, or be in Burp Suite scope if scope mode is enabled.
- The request must look API-like.
- The request must not be a configured refresh-token endpoint.
- The request method must be allowed.

API-like requests are detected using simple heuristics such as:

- URL path contains `/api/`
- URL path ends in `.json`
- request or response content type suggests JSON or form data
- request accepts JSON

## HTTP Method Safety

By default, the extension actively tests only safer HTTP methods:

```text
GET
HEAD
OPTIONS
```

Requests using methods such as the following are skipped unless **Allow unsafe methods** is enabled:

```text
POST
PUT
PATCH
DELETE
```

Enable unsafe methods only when you have explicit authorization and understand the target application's behavior. Mutating requests can create, update, delete, or otherwise alter application data.

## Live Token Refresh Handling

Many applications rotate access tokens during testing. If the extension replays an old captured request with an expired token, later tests may incorrectly receive `401 Unauthorized`.

To reduce that problem, the extension can watch a configured refresh-token endpoint and update the auth header used for later tests.

### Configuration

Use these fields:

| Field | Example | Description |
|---|---|---|
| Refresh endpoint regex/contains | `/auth/refresh` | URL substring or regex used to identify refresh-token responses. |
| Refresh token JSON field | `access_token` | JSON response field containing the new token. |
| Auth header value template | `Bearer {token}` | Template used to build the auth header value. |

Examples:

```text
Auth header name: Authorization
Refresh endpoint regex/contains: /auth/refresh
Refresh token JSON field: access_token
Auth header value template: Bearer {token}
```

For a custom token header:

```text
Auth header name: X-Auth-Token
Refresh token JSON field: token
Auth header value template: {token}
```

### Behavior

When a live Proxy response matches the refresh endpoint pattern:

1. The extension reads the response body.
2. It extracts the configured JSON field.
3. It builds the latest auth header value using the template.
4. It applies that latest token before each non-authentication test request.

Authentication removal tests still remove the auth header on purpose.

Refresh-token endpoints are skipped from active testing.

## Tests Performed

### 1. Authentication Removal

The extension clones the original request and removes the configured auth header case-insensitively.

Example:

```http
Authorization: Bearer eyJ...
```

is removed from the modified request.

The modified request is sent and compared to the baseline authenticated response.

Severity logic:

- **High**: unauthenticated response returns `200`, `201`, or `204` and looks similar to the authenticated baseline.
- **Medium**: unauthenticated response differs but still contains sensitive-looking JSON keys.
- **Info**: unauthenticated response returns `401` or `403`, or no automated issue is detected.

Sensitive-looking keys include values such as:

```text
token
access_token
refresh_token
password
secret
role
isAdmin
permissions
```

### 2. Input Validation

The extension tests enabled input locations one value at a time:

- query parameters
- JSON body fields
- form body fields
- selected custom headers

It replaces each value with one special character at a time:

```text
! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~
```

It records how the application responds for each character.

The report includes a special-character allowance matrix for every endpoint:

| Parameter / Field | Allowed special characters | Rejected / errored special characters | Suspicious accepted characters |
|---|---|---|---|
| JSON Field: name | `!` `#` `$` | `<` `"` | `"` |

The extension flags suspicious behavior when it sees:

- `500` responses
- stack traces
- SQL/runtime error patterns
- special characters reflected in risky contexts
- validation-related behavior changes

### 3. Length Validation

The extension replaces each enabled parameter, body field, JSON field, or selected header with repeated `A` characters.

Payload lengths:

```text
256
1024
4096
10000
```

It flags suspicious behavior such as:

- `500` responses
- stack traces
- runtime exceptions
- SQL/error patterns
- unusual server behavior

Clean length tests are summarized as informational results.

### 4. Extra Parameter Check

For JSON object bodies, the extension injects:

```json
"test": "test"
```

For form bodies, it injects:

```text
test=test
```

It checks whether the extra parameter appears to be accepted, reflected, or causes meaningful response changes.

This is intentionally simple and low-risk. It is not a full mass-assignment exploitation engine. Treat results as triage evidence requiring manual review.

## Reporting

The extension exports a Markdown report with:

- title
- date/time
- scope/domain
- request source mode
- refresh-token tracking configuration
- list of all tested endpoints
- summary by severity
- endpoint-grouped results

Report structure:

```markdown
# API Auth & Validation Tester Report

## Endpoints Tested
- GET api.example.com/api/user
- POST api.example.com/api/profile

## GET api.example.com/api/user

### Authentication
...

### Input Validation
...

### Extra Parameter Check
...
```

Each recorded result includes:

- test type
- severity
- original status
- modified status
- modified parameter/header/body field
- payload used
- evidence summary
- full request content
- full response content
- recommendation

## Important Security Warning About Reports

Reports may contain sensitive information because the extension intentionally stores full request and response evidence.

Reports may include:

- access tokens
- refresh tokens
- cookies
- authorization headers
- API keys
- usernames
- emails
- personal data
- internal IDs
- business data

Do not publish generated reports without reviewing and redacting them first.

## Logs

The extension logs important scan activity in its Burp tab, including:

- captured API requests
- skipped requests and reasons
- token refresh updates
- when latest live token is applied
- test start/completion messages
- report export status

Common skip reasons:

- out of scope
- not API-like
- unsafe method disabled
- configured refresh endpoint skipped
- duplicate request in history/both mode

## Limitations

This is an alpha tool and uses heuristic detection.

Known limitations:

- JSON parsing is lightweight and may not fully support deeply nested or complex JSON structures.
- Token extraction currently expects a JSON string field such as `"access_token": "..."`.
- Input validation findings are heuristic and may produce false positives or false negatives.
- Special-character acceptance does not automatically mean vulnerability.
- Extra parameter reflection does not automatically mean mass assignment.
- Authorization logic still requires manual verification across users, roles, and tenants.
- Multipart handling is graceful but not deeply mutation-aware.
- The extension does not currently perform recursive JSON mutation for every nested object/array path.
- Full request/response reporting can generate large Markdown files.

## Safety Guidance

Use this extension only when you are authorized to test the target.

Recommended workflow:

1. Start with safe methods only.
2. Confirm scope/domain configuration.
3. Confirm refresh-token configuration if the application rotates tokens.
4. Review skipped-request logs.
5. Enable unsafe methods only when permitted.
6. Validate findings manually before reporting.
7. Redact exported reports before sharing.

## Disclaimer

This project is provided for authorized security testing and educational purposes only.

This extension is a pentester productivity aid, not a replacement for professional judgment, manual verification, or a complete security assessment.

The authors and contributors are not responsible for misuse, unauthorized testing, data loss, account lockouts, service disruption, or any other damage caused by this tool.

By using this extension, you are responsible for ensuring that your testing is legal, authorized, and controlled.

## Project Status

Recommended public release label:

```text
Alpha
```

The extension is functional but intentionally conservative and heuristic. Contributions, testing feedback, and detection improvements are welcome.

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
