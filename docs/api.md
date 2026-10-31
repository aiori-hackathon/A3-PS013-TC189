# API

Interactive API documentation is available at `/docs`.

## Main endpoints

- `POST /api/investigations`
- `GET /api/investigations`
- `GET /api/investigations/{id}/summary`
- `GET /api/investigations/{id}/sources`
- `POST /api/investigations/{id}/evidence`
- `GET /api/timeline`
- `GET /api/events/{event_id}`
- `GET /api/investigations/{id}/correlations`
- `POST /api/investigations/{id}/correlations`
- `POST /api/correlations/{id}/dismiss`
- `GET /api/events/{id}/correlations`
- `GET /api/investigations/{id}/report.pdf`
- `GET /api/investigations/{id}/export/{dataset}.csv`

## Quality endpoints

- `/api/quality/investigations/{id}/coverage`
- `/api/quality/investigations/{id}/gaps`
- `/api/quality/investigations/{id}/parsing`
- `/api/quality/investigations/{id}/timestamps`
- `/api/quality/investigations/{id}/integrity`
- `/api/quality/investigations/{id}/duplicates`

## Agent endpoints

Agent endpoints require a bearer token and are documented in `/docs`.
