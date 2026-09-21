# TraceGuard API Documentation

## Cloud Accounts

### `GET /api/accounts`
- **Description:** List all configured cloud accounts.
- **Request Body:** None
- **Response:**
  ```json
  { "accounts": [{ "id": "1", "name": "Prod AWS", "provider": "aws", "createdAt": "..." }] }
  ```
- **Error Codes:** 401 Unauthorized, 500 Internal Error
- **Example:** `curl -X GET http://localhost:3000/api/accounts`

### `POST /api/accounts`
- **Description:** Create a new cloud account (credentials will be AES-encrypted).
- **Request Body:**
  ```json
  { "name": "Prod AWS", "provider": "aws", "credentials": { "accessKeyId": "...", "secretAccessKey": "..." } }
  ```
- **Response:**
  ```json
  { "id": "1", "status": "created" }
  ```
- **Error Codes:** 400 Bad Request
- **Example:** `curl -X POST -H "Content-Type: application/json" -d '{"name":"AWS"}' http://localhost:3000/api/accounts`

### `GET /api/accounts/[id]`
- **Description:** Get details for a single account.
- **Request Body:** None
- **Response:** Account object (without raw credentials).
- **Example:** `curl -X GET http://localhost:3000/api/accounts/1`

### `DELETE /api/accounts/[id]`
- **Description:** Delete an account.
- **Example:** `curl -X DELETE http://localhost:3000/api/accounts/1`

### `POST /api/accounts/[id]/scan`
- **Description:** Run a scan for a specific service on an account.
- **Request Body:**
  ```json
  { "service": "s3" }
  ```
- **Response:**
  ```json
  { "status": "success", "findingsCount": 5 }
  ```
- **Example:** `curl -X POST -H "Content-Type: application/json" -d '{"service":"s3"}' http://localhost:3000/api/accounts/1/scan`

### `POST /api/accounts/validate`
- **Description:** Validate credentials before saving.
- **Request Body:** Same as `POST /api/accounts`
- **Response:** `{ "valid": true }`

## Security Data

### `GET /api/findings`
- **Description:** List all findings.
- **Query Params:** `?severity=high&status=open&provider=aws`
- **Response:** Array of finding objects.
- **Example:** `curl -X GET http://localhost:3000/api/findings?severity=critical`

### `GET /api/posture`
- **Description:** Security posture summary.
- **Response:**
  ```json
  { "critical": 2, "high": 5, "medium": 12, "low": 20 }
  ```

## AI Investigation

### `POST /api/investigate`
- **Description:** Start AI investigation pipeline for a finding. Streams response (Server-Sent Events).
- **Request Body:**
  ```json
  { "findingId": "finding-123" }
  ```
- **Response:** Text stream of AI reasoning steps.

### `POST /api/approve`
- **Description:** Approve an AI-suggested remediation action.
- **Request Body:**
  ```json
  { "investigationId": "inv-123", "action": "block_public_access" }
  ```
- **Response:** `{ "status": "success", "actionId": "act-123" }`
