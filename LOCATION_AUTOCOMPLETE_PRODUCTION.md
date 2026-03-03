# Location Autocomplete System - Production Documentation

## Overview

Production-ready location autocomplete system with aggressive multi-layer caching designed to reduce external API calls by 80-95%.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           USER TYPING                                        │
│                           "new york"                                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  FRONTEND (React + Vite)                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ useLocationAutocomplete Hook                                         │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│  │  │   Debounce   │  │  In-Memory   │  │   Request    │               │   │
│  │  │    450ms     │→ │  Cache       │→ │  Deduplication│               │   │
│  │  │              │  │  (Map)       │  │              │               │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
│  │         ↓                    ↑                    ↓                   │   │
│  │  ┌──────────────────────────────────────────────────────────────┐    │   │
│  │  │                    localStorage Cache                         │    │   │
│  │  │              TTL: 10 min | Max: 20 entries                    │    │   │
│  │  └──────────────────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ (API Call if cache miss)
┌─────────────────────────────────────────────────────────────────────────────┐
│  BACKEND (FastAPI + Redis + Celery)                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  /api/v1/location/autocomplete                                       │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│  │  │   Query      │  │    Redis     │  │   Request    │               │   │
│  │  │ Normalization│→ │    Cache     │→ │  Deduplication│               │   │
│  │  │              │  │  (15 min)    │  │              │               │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
│  │         ↓                    ↑                    ↓                   │   │
│  │  ┌──────────────────────────────────────────────────────────────┐    │   │
│  │  │              Celery Task (Async API Call)                     │    │   │
│  │  │              LocationIQ External API                          │    │   │
│  │  └──────────────────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Caching Layers

### Layer 1: Frontend In-Memory Cache (Fastest)
- **Storage**: JavaScript `Map` in hook closure
- **TTL**: Session-only (cleared on page reload)
- **Hit Rate**: ~40% for repeated queries in same session
- **Latency**: <1ms

### Layer 2: Frontend localStorage Cache (Fast)
- **Storage**: Browser localStorage
- **TTL**: 10 minutes
- **Max Size**: 20 entries
- **Hit Rate**: ~30% for returning users
- **Latency**: <5ms

### Layer 3: Backend Redis Cache (Medium)
- **Storage**: Redis (shared across all users)
- **TTL**: 15 minutes (900 seconds)
- **Key Format**: `location:query:<normalized_query>`
- **Hit Rate**: ~20% for popular queries across users
- **Latency**: <10ms

### Layer 4: External API (Slowest)
- **Provider**: LocationIQ
- **Rate Limit**: 5,000 requests/day, 2 requests/second
- **Latency**: 100-500ms

## Expected Cache Performance

| Scenario | Cache Layer Hit | API Calls Saved | Latency |
|----------|----------------|-----------------|---------|
| Same user, same query (session) | In-Memory | 100% | <1ms |
| Same user, same query (within 10 min) | localStorage | 100% | <5ms |
| Different user, same query (within 15 min) | Redis | 100% | <10ms |
| New query | API | 0% | 100-500ms |

**Overall API Call Reduction: 80-95%**

## Features

### Frontend (`useLocationAutocomplete`)

| Feature | Default | Description |
|---------|---------|-------------|
| `debounceMs` | 450ms | Wait for user to stop typing |
| `minLength` | 3 | Minimum characters before search |
| `minRequestInterval` | 800ms | Minimum time between API calls |
| `maxCacheSize` | 20 | Maximum localStorage entries |
| `cacheTTL` | 600000ms | localStorage cache lifetime (10 min) |
| `limit` | 10 | Max results per query |
| `countrycodes` | - | Restrict to countries (e.g., "us,ca") |

### Backend (`/api/v1/location/autocomplete`)

| Feature | Description |
|---------|-------------|
| Query Normalization | Trim, lowercase, remove special chars |
| Prefix Caching | Cache partial queries for faster typeahead |
| Request Deduplication | Prevent duplicate concurrent API calls |
| Rate Limiting | Enforce minimum interval between requests |
| Graceful Degradation | Fallback if Redis/Celery unavailable |

## API Reference

### Frontend Hook

```javascript
import { useLocationAutocomplete } from '@/hooks/useLocationAutocomplete'

function MyComponent() {
  const {
    query,
    results,
    loading,
    error,
    selected,
    setQuery,
    select,
    clear,
    hasSelection,
    hasResults,
  } = useLocationAutocomplete({
    debounceMs: 450,
    minLength: 3,
    limit: 10,
    countrycodes: 'us',
    minRequestInterval: 800,
  })
  
  return (
    <input
      value={query}
      onChange={(e) => setQuery(e.target.value)}
      placeholder="Search location..."
    />
  )
}
```

### Backend Endpoint

**GET** `/api/v1/location/autocomplete`

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `q` | string | Yes | - | Search query (min 3 chars) |
| `limit` | integer | No | 10 | Results count (1-20) |
| `countrycodes` | string | No | - | ISO country codes (e.g., "us,ca") |
| `viewbox` | string | No | - | Bounding box: "x1,y1,x2,y2" |
| `bounded` | boolean | No | false | Restrict to viewbox |
| `use_cache` | boolean | No | true | Use cache if available |

**Response:**
```json
{
  "results": [
    {
      "place_id": "123456",
      "display_name": "New York, NY, USA",
      "display_place": "New York",
      "display_address": "NY, USA",
      "lat": 40.7128,
      "lon": -74.0060,
      "address": {
        "name": "",
        "road": "",
        "city": "New York",
        "state": "New York",
        "postcode": "",
        "country": "United States",
        "country_code": "us"
      },
      "type": "city",
      "importance": 0.9
    }
  ],
  "cached": true,
  "cache_source": "redis",
  "query_time_ms": 2.34
}
```

### Health Check

**GET** `/api/v1/location/health`

```json
{
  "service": "locationiq",
  "configured": true,
  "redis_connected": true,
  "cache_keys": 142,
  "celery_available": true
}
```

## Configuration

### Backend (.env)

```env
# LocationIQ API
LOCATIONIQ_API_KEY=pk.your_api_key_here
LOCATIONIQ_BASE_URL=https://api.locationiq.com/v1

# Redis (required for caching)
REDIS_URL=redis://localhost:6379/0

# Celery (optional, for async API calls)
CELERY_BROKER_URL=redis://localhost:6379/0
```

### Frontend

No configuration needed. Uses backend proxy for API calls.

## Usage Example

### LocationModal Component

```jsx
import LocationAutocompleteInput from '@/components/LocationAutocompleteInput'

function LocationModal({ onClose, onSaved }) {
  const { setValue, watch } = useForm()
  
  const handleLocationSelect = ({ display_name, latitude, longitude, address }) => {
    setValue('address', display_name)
    setValue('latitude', latitude)
    setValue('longitude', longitude)
    if (address?.city) setValue('city', address.city)
    if (address?.state) setValue('state', address.state)
  }
  
  return (
    <LocationAutocompleteInput
      value={watch('name')}
      onChange={(e) => setValue('name', e.target.value)}
      latitude={watch('latitude')}
      longitude={watch('longitude')}
      onLocationSelect={handleLocationSelect}
      onLocationClear={() => {
        setValue('latitude', null)
        setValue('longitude', null)
      }}
      options={{
        countrycodes: 'us',
        limit: 10,
        debounceMs: 450,
        minRequestInterval: 800,
      }}
    />
  )
}
```

## Testing

### Backend Tests

```bash
cd Alert-system-backend
source venv/bin/activate

# Run location tests
pytest app/tests/test_location_v2.py -v

# Run with coverage
pytest app/tests/test_location_v2.py -v --cov=app.core.location_cache --cov=app.api.location_v2
```

### Frontend Testing

```bash
cd alert-system-frontend

# Build verification
npm run build

# Run in development
npm run dev
```

## Monitoring

### Cache Statistics

```bash
# Get cache stats
curl https://your-api.com/api/v1/location/stats

# Health check
curl https://your-api.com/api/v1/location/health
```

### Key Metrics to Monitor

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Cache Hit Rate | >80% | <60% |
| API Calls/Day | <1000 | >4000 |
| P95 Latency | <50ms | >200ms |
| Error Rate | <1% | >5% |

## Troubleshooting

### High API Call Volume

**Symptoms**: Approaching LocationIQ rate limits

**Solutions**:
1. Increase `cacheTTL` in frontend hook
2. Increase Redis TTL in backend
3. Reduce `limit` parameter
4. Add more restrictive `countrycodes`

### Cache Not Working

**Symptoms**: Every query hits API

**Check**:
1. Redis connection: `/api/v1/location/health`
2. Frontend console for localStorage errors
3. Backend logs for cache errors

### Slow Response Times

**Symptoms**: Queries taking >500ms

**Check**:
1. Cache hit rate (should be >80%)
2. LocationIQ API status
3. Redis latency

## Security

- **API Key Protection**: LocationIQ key stored in backend, never exposed to frontend
- **Input Validation**: Query sanitization prevents injection attacks
- **Rate Limiting**: Backend enforces minimum intervals between requests
- **CORS**: Restricted to allowed origins only

## Performance Optimization Tips

1. **Restrict by Country**: Use `countrycodes: 'us'` to reduce irrelevant results
2. **Tune Debounce**: Increase `debounceMs` for slower typers
3. **Limit Results**: Use `limit: 8` instead of default 10
4. **Monitor Cache**: Regularly check cache hit rates
5. **Clear Stale Cache**: Use `DELETE /api/v1/location/cache` endpoint

## Folder Structure

```
Alert-system-backend/
├── app/
│   ├── api/
│   │   └── location_v2.py          # FastAPI endpoint with caching
│   ├── core/
│   │   ├── location_cache.py       # Redis cache utility
│   │   └── ...
│   ├── tests/
│   │   ├── test_location_v2.py     # Backend tests
│   │   └── ...
│   ├── tasks.py                    # Celery tasks (includes location task)
│   ├── main.py                     # App initialization
│   └── ...
└── .env

alert-system-frontend/
├── src/
│   ├── hooks/
│   │   └── useLocationAutocomplete.js  # React hook
│   ├── components/
│   │   └── LocationAutocompleteInput.jsx  # Reusable component
│   ├── types/
│   │   └── location.js             # TypeScript types (JSDoc)
│   ├── services/
│   │   └── api.js                  # API service (locationAutocompleteAPI)
│   └── pages/
│       └── OtherPages.jsx          # LocationModal usage
└── ...
```

## Changelog

### v2.0.0 (Current)
- Added Redis caching layer (15 min TTL)
- Implemented request deduplication
- Added Celery async task support
- Frontend localStorage caching (10 min TTL)
- Query normalization for consistent caching
- Rate limiting (800ms minimum between requests)
- Comprehensive test suite

### v1.0.0 (Previous)
- Basic LocationIQ integration
- Simple frontend debouncing
- No caching layer
