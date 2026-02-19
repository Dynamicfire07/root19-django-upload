# Root 19 API Documentation

This document covers the question APIs, authentication, and the valid subject options for filtering.

## Base URL

- Production: `https://app.root19.com`
- Local: `http://127.0.0.1:8000`

## Authentication

All question API endpoints require an API key.

Generate/manage keys from the staff panel:

- `/staff/api-keys/`

Supported headers:

- `X-API-Key: <your_key>`
- `Authorization: Bearer <your_key>`

If your client cannot send custom headers, you can also pass:

- `?api_key=<your_key>` in the URL query string

If the key is missing, invalid, expired, inactive, or a limited key has reached its limit, the API returns `401`.

## Subject Options

Use `subject` or `session_code` in query params.

### Supported subjects

| Subject | session_code |
|---|---|
| Biology | `610` |
| Chemistry | `620` |
| Physics | `625` |

### Current session options in the database

`session` values currently present:

- `Feb/March`
- `May/June`
- `Oct/Nov`

## Endpoints

### 1) List Questions

`GET /api/questions/`

Returns paginated question records with all DB fields plus normalized helper fields:

- `image_link`
- `image_src`
- `question`
- `question_type`
- `subject`

#### Query parameters

- `q` (text search)
- `question_id`
- `session_code`
- `subject` (`Biology`, `Chemistry`, `Physics`, or code like `625`)
- `session`
- `year`
- `paper_code`
- `variant`
- `subtopic`
- `question_type`
- `answer`
- `limit` (default `50`, max `500`)
- `offset` (default `0`)
- `order_by`
- `sort` (`asc` or `desc`)
- `include_image_base64` (`1` default, or `0`)

#### Example

```bash
curl -H "X-API-Key: r19_xxx" \
  "https://app.root19.com/api/questions/?subject=Physics&session=May/June&limit=10&offset=0&include_image_base64=0"
```

URL-only key example:

```text
https://app.root19.com/api/questions/?api_key=r19_xxx&subject=Physics&session=May/June&limit=10&offset=0&include_image_base64=0
```

### 2) Question Detail

`GET /api/questions/<question_id>/`

Returns a single question with all DB fields + normalized helper fields.

#### Example

```bash
curl -H "X-API-Key: r19_xxx" \
  "https://app.root19.com/api/questions/0/?include_image_base64=0"
```

## Response shape (list)

```json
{
  "count": 5354,
  "limit": 10,
  "offset": 0,
  "returned": 10,
  "results": [
    {
      "question_id": "0",
      "session_code": "625",
      "session": "Oct/Nov",
      "year": 2016,
      "paper_code": "2",
      "variant": "1",
      "subtopic": "Motion",
      "answer": "A",
      "image_url": "https://...",
      "image_base64": null,
      "image_link": "https://...",
      "image_src": "https://...",
      "question": "....",
      "question_type": "Motion",
      "subject": "Physics"
    }
  ]
}
```
