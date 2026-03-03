# Location Autocomplete with LocationIQ

Secure, production-ready location autocomplete implementation using LocationIQ API.

## Features

- **Secure API Key Handling**: Backend proxy hides LocationIQ API key from frontend
- **Server-Side Caching**: 48-hour cache (free tier compliant) reduces API calls
- **Rate Limiting**: Handles LocationIQ rate limits gracefully
- **Input Validation**: Sanitizes and validates all user input
- **Debounced Search**: 150ms debounce prevents excessive API calls
- **Auto-Fill Coordinates**: Latitude/longitude automatically populated on selection
- **Reusable Components**: Hook and component can be used in any form

## Configuration

### Backend (.env)

Add your LocationIQ API key to the backend `.env` file:

```env
LOCATIONIQ_API_KEY=pk.your_actual_api_key_here
LOCATIONIQ_BASE_URL=https://api.locationiq.com/v1
```

**Get your API key**: https://locationiq.com/

### Frontend

No additional configuration needed. The frontend calls the backend proxy which injects the API key.

## Usage

### In Forms (LocationModal Example)

```jsx
import LocationAutocompleteInput from '@/components/LocationAutocompleteInput'

function MyForm() {
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
      placeholder="Search for a location"
      options={{
        countrycodes: 'us', // Restrict to US
        limit: 10,
      }}
    />
  )
}
```

### Using the Hook Directly

```jsx
import { useLocationAutocomplete } from '@/hooks/useLocationAutocomplete'

function MyComponent() {
  const {
    query,
    suggestions,
    loading,
    error,
    selected,
    setQuery,
    select,
  } = useLocationAutocomplete({
    debounceMs: 150,
    minLength: 3,
    limit: 10,
    countrycodes: 'us,ca',
  })
  
  return (
    <div>
      <input value={query} onChange={(e) => setQuery(e.target.value)} />
      {suggestions.map(s => (
        <div key={s.place_id} onClick={() => select(s)}>
          {s.display_name}
        </div>
      ))}
    </div>
  )
}
```

## API Reference

### Backend Endpoint

**GET** `/api/v1/location/autocomplete`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `q` | string | Yes | Search query (min 3 characters) |
| `limit` | integer | No | Number of results (1-20, default: 10) |
| `countrycodes` | string | No | Comma-separated ISO country codes (e.g., `us,ca`) |
| `viewbox` | string | No | Bounding box for biasing: `x1,y1,x2,y2` |
| `bounded` | boolean | No | Restrict results to viewbox only |

**Response:**
```json
{
  "results": [
    {
      "place_id": "123456",
      "display_name": "Empire State Building, New York, NY, USA",
      "display_place": "Empire State Building",
      "display_address": "New York, NY, USA",
      "lat": 40.748817,
      "lon": -73.985428,
      "address": {
        "name": "Empire State Building",
        "road": "5th Avenue",
        "city": "New York",
        "state": "New York",
        "postcode": "10118",
        "country": "United States",
        "country_code": "us"
      },
      "type": "building",
      "importance": 0.9
    }
  ],
  "cached": false
}
```

**GET** `/api/v1/location/health`

Check service status:
```json
{
  "service": "locationiq",
  "configured": true,
  "cache_size": 42
}
```

### Frontend Service

```javascript
import { locationAutocompleteAPI } from '@/services/api'

// Search for locations
const { data } = await locationAutocompleteAPI.search('Empire State', {
  limit: 10,
  countrycodes: 'us',
})

// Check health
const { data } = await locationAutocompleteAPI.health()
```

### Hook Options

```javascript
useLocationAutocomplete({
  debounceMs: 150,        // Debounce delay (default: 150)
  minLength: 3,           // Min characters before search (default: 3)
  limit: 10,              // Max results (default: 10)
  countrycodes: 'us,ca',  // Restrict to countries
  viewbox: '-180,-90,180,90', // Bias to bounding box
  bounded: false,         // Restrict to viewbox
})
```

## Rate Limits (LocationIQ Free Tier)

- **5,000 requests/day**
- **2 requests/second**

### Optimization Strategies Implemented

The implementation includes multiple layers of optimization to stay well within rate limits:

| Optimization | Default | Impact |
|--------------|---------|--------|
| **Debounce delay** | 500ms | Waits for user to stop typing before searching |
| **Min request interval** | 1,200ms | Enforces 1.2s between API calls (max ~50 req/min) |
| **Minimum characters** | 3 | Prevents searches on short, useless queries |
| **Result limit** | 8 | Reduces response size and processing |
| **Country restriction** | 'us' | Faster, more relevant results |
| **Client-side caching** | Session + 48h localStorage | Repeated queries don't hit API |
| **Server-side caching** | 48 hours | Backend cache shared across all users |

### Example: Typing "new york"

**Before optimization:**
```
n → (no search, < 3 chars)
ne → (no search, < 3 chars)
new → API call #1
new  → API call #2
new y → API call #3
new yo → API call #4
new yor → API call #5
new york → API call #6
Total: 6 API calls
```

**After optimization:**
```
n → (no search, < 3 chars)
ne → (no search, < 3 chars)
new → wait 500ms... API call #1 (cached)
new  → (debounce resets, no API call yet)
new y → (debounce resets, no API call yet)
new yo → (debounce resets, no API call yet)
new yor → (debounce resets, no API call yet)
new york → wait 500ms... API call #2 (cached)
Total: 2 API calls (66% reduction)

Subsequent searches for same query: 0 API calls (loaded from cache)
```

### Caching Policy

Per LocationIQ free tier terms:
- **Maximum cache duration: 48 hours**
- Cache key includes: query + countrycodes + viewbox
- **Client-side cache**: localStorage persists across page reloads (48h)
- **Server-side cache**: In-memory cache shared across all users (48h)
- Automatic cleanup of expired entries

### When Cache Helps

1. **Same user searches again**: Loaded from localStorage instantly
2. **Different user searches same location**: Server cache serves result
3. **User pauses mid-typing then continues**: Previous results cached
4. **Page refresh**: Cache restored from localStorage

## Caching Policy

Per LocationIQ free tier terms:
- **Maximum cache duration: 48 hours**
- Cache key includes: query + countrycodes + viewbox
- Short-term cache for repeated identical requests (5 minutes)
- Automatic cleanup of expired entries

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Rate limit (429) | Shows user-friendly message, suggests waiting |
| API downtime (5xx) | Graceful error, allows manual entry |
| No results | Shows "No locations found" |
| Invalid query | Returns validation error |
| Network timeout | Retries up to 2 times |

## Testing

Run backend tests:
```bash
cd Alert-system-backend
pytest app/tests/test_location.py -v
```

## Files Modified/Created

### Backend
- `app/config.py` - Added LOCATIONIQ_API_KEY, LOCATIONIQ_BASE_URL
- `app/api/location.py` - New proxy endpoint with caching, validation, rate limiting
- `app/main.py` - Registered location router
- `app/tests/test_location.py` - Unit and integration tests

### Frontend
- `src/services/api.js` - Added locationAutocompleteAPI service
- `src/hooks/useLocationAutocomplete.js` - Reusable hook with debouncing, caching
- `src/components/LocationAutocompleteInput.jsx` - Reusable input component
- `src/pages/OtherPages.jsx` - Updated LocationModal to use autocomplete

## Troubleshooting

**"Location service temporarily unavailable"**
- Check that LOCATIONIQ_API_KEY is set in backend .env
- Verify API key is valid at https://locationiq.com/

**No suggestions appearing**
- Ensure query is at least 3 characters
- Check browser console for API errors
- Verify backend is running and accessible

**Rate limit errors**
- Wait a moment between searches
- Cache is automatically used for repeated queries
- Consider upgrading LocationIQ plan for higher limits
