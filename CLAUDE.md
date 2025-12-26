# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecuriScan AI V4 is a **bilingual (Turkish/English) cybersecurity vulnerability scanner** web application with a full-stack architecture. It performs AI-powered security analysis using Google Gemini 3 Flash via OpenRouter, presenting results through an interactive terminal-style interface and comprehensive reporting dashboard. The application emphasizes security-first design with SSRF protection, rate limiting, and proper API key management.

## Development Commands

### Running the Application

**All-in-one development mode** (recommended):
```bash
npm run dev  # Starts both backend (port 3001) and frontend (port 3000)
```

**Separate terminals**:
```bash
npm run dev:server   # Backend only (Express on port 3001)
npm run dev:client   # Frontend only (Vite dev server)
```

**Production build**:
```bash
npm run build         # Builds both client and server
npm run build:server  # Builds server only
```

### Environment Setup

1. **Create `.env.local`** from `.env.example`:
   ```bash
   cp .env.example .env.local
   ```

2. **Configure environment variables**:
   ```bash
   OPENROUTER_API_KEY=sk-or-v1-your_api_key_here  # Or PLACEHOLDER_API_KEY for mock mode
   PORT=3001
   NODE_ENV=development
   CLIENT_URL=http://localhost:3000
   ```

3. **Mock Mode**: If `OPENROUTER_API_KEY=PLACEHOLDER_API_KEY`, the backend runs in mock mode with sample data (perfect for frontend development).

**IMPORTANT**: API keys are **NEVER** exposed to the client. They exist only in the backend server environment.

## Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT (Port 3000)                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  React 19 + TypeScript + Vite                       │   │
│  │  - Custom hooks (useScan, useTranslation)           │   │
│  │  - Feature-based components                         │   │
│  │  - Tailwind CSS (cyber theme)                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│                    Axios (via proxy)                         │
│                           │                                  │
└───────────────────────────┼──────────────────────────────────┘
                            │
                         /api/*
                            │
┌───────────────────────────┼──────────────────────────────────┐
│                   SERVER (Port 3001)                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Express.js + TypeScript                            │   │
│  │  - CORS, Helmet, Rate Limiting                      │   │
│  │  - SSRF Protection (URL validator)                  │   │
│  │  - OpenRouter integration                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                  │
└───────────────────────────┼──────────────────────────────────┘
                            │
                   OpenRouter API
                            │
                  Google Gemini 3 Flash
```

### Application State Flow

```
IDLE State
   │
   ├──> User enters URL + clicks scan
   │
   ├──> Frontend validation (useScan hook)
   │       ├─ Empty check
   │       ├─ URL pattern validation
   │       └─ Protocol normalization (add https://)
   │
   ├──> POST /api/scan { url, lang }
   │
   ├──> Backend validation
   │       ├─ SSRF check (block localhost, private IPs)
   │       ├─ Rate limit check (10 req/15min)
   │       └─ OpenRouter API call
   │
SCANNING State (parallel operations)
   │
   ├──> Terminal animation (visual feedback)
   ├──> AI analysis (backend → OpenRouter)
   │
   ├──> Terminal completes → handleTerminalComplete()
   ├──> API responds → setReport(result)
   │
COMPLETE State
   │
   ├──> Report displays with paywall blur
   ├──> User "unlocks" → setIsPaid(true)
   ├──> Full report accessible
   │
   └──> Language switch → Re-fetch report with new lang
```

### Core Application Components

#### **Backend (Express)**

**server/index.ts** - Express server setup
- Helmet for security headers
- CORS configuration for localhost
- Rate limiting (10 requests per 15 minutes)
- Error handling middleware
- API routes mounting

**server/services/openrouter.service.ts** - AI Integration
- OpenRouter API client
- Model: `google/gemini-flash-1.5-8b`
- Prompt engineering for security analysis
- Mock mode fallback for development
- Response parsing to SecurityReport type

**server/utils/url-validator.ts** - SSRF Protection
- Blocks localhost, 127.0.0.1
- Blocks private IP ranges (10.x, 192.168.x, 172.16-31.x)
- Blocks link-local (169.254.x)
- IPv6 private range protection

**server/routes/scan.routes.ts** - API Endpoints
- `POST /api/scan` - Main scanning endpoint
  - Request: `{ url: string, lang: 'tr' | 'en' }`
  - Response: `SecurityReport` object

#### **Frontend (React)**

**src/app.tsx** - Main Application
- Uses `useTranslation()` for language management
- Uses `useScan()` for scan orchestration
- Manages `isPaid` state for paywall
- Renders components based on scan status:
  - `IDLE`: Hero section with URL input form
  - `SCANNING`: Terminal animation with loading state
  - `COMPLETE`: Report dashboard with optional paywall
  - `ERROR`: Error message with retry option

**src/hooks/use-scan.ts** - Scan State Management
- Manages all scan-related state (url, status, report, error, validationError)
- Encapsulates URL validation logic
- Handles scan initiation and cleanup
- Synchronizes terminal completion with report availability
- Provides clean API: `startScan()`, `reset()`, `handleTerminalComplete()`

**src/hooks/use-translation.ts** (via src/i18n/index.ts)
- Language state with localStorage persistence
- Returns: `{ lang, t, changeLanguage }`
- Translations loaded from `src/i18n/locales/{tr,en}.ts`

**src/services/scan.service.ts** - Backend API Client
- Calls backend `/api/scan` endpoint
- Uses centralized Axios client from `lib/api/client.ts`
- Replaces old `geminiService.ts` (which was mock-only)

### Feature Components

**src/features/scanner/components/scan-terminal.tsx**
- Animated terminal with typewriter effect
- Displays progressive scan logs (8 steps)
- Sequences loaded from `constants/terminal-sequences.ts`
- Progress bar synchronized with log count
- Fires `onComplete` callback when animation finishes

**src/features/report/components/report-dashboard.tsx**
- Multi-section security report:
  - **Executive Briefing**: Overall score, critical findings summary
  - **Vulnerabilities**: Expandable vulnerability cards
  - **Action Plan**: Sortable table (priority/time-based)
  - **Tech Stack**: Detected technologies with CVE risks
  - **Network Intel**: DNS, SSL, headers, ports analysis
- Uses Recharts for pie chart visualization
- Calculates critical findings via CVSS score sorting

**src/features/report/components/vulnerability-card.tsx**
- Expandable card with severity color-coding
- Displays:
  - Title, location, CVSS score
  - Description and exploit example (PoC)
  - Remediation steps
  - Exploit chain (multi-step attack paths)
- Severity colors: CRITICAL (red), HIGH (orange), MEDIUM (yellow), LOW/INFO (blue)

**src/features/paywall/components/paywall-overlay.tsx**
- Modal overlay with pricing information
- Simulates payment flow (2-second delay)
- Calls `onUnlock()` to set `isPaid` state
- **Structure only** - no real payment integration

### Data Model (TypeScript Types)

**src/types/security-report.types.ts**
```typescript
interface SecurityReport {
  targetUrl: string;
  scanDate: string;
  overallScore: number;
  vulnerabilities: Vulnerability[];
  actionPlan: ActionPlanItem[];
  techStack: TechStackItem[];
  networkInfo: NetworkInfo;
}

interface Vulnerability {
  id: string;
  title: string;
  severity: Severity;  // CRITICAL | HIGH | MEDIUM | LOW | INFO
  cvssScore: number;
  description: string;
  location: string;
  exploitExample: string;
  remediation: string;
  exploitablePaths: ExploitPath[];
  relatedCVEs: string[];
}
```

**src/types/scan.types.ts**
```typescript
type ScanStatus = 'IDLE' | 'SCANNING' | 'COMPLETE' | 'ERROR';
```

### Styling System

**Tailwind CSS with Custom Theme**:
```javascript
// tailwind.config.js
colors: {
  'cyber-green': '#00ff41',
  'cyber-black': '#0a0a0a',
  'cyber-dark': '#111111',
}
```

**Design Patterns**:
- Glass-morphism: `backdrop-blur-sm`, `bg-white/5`
- Matrix-style grid background
- Monospace fonts (`font-mono`) for technical aesthetic
- Custom glow effects: `shadow-[0_0_50px_rgba(0,255,65,0.1)]`

**Animations**:
- `animate-fade-in`: Page transitions
- `animate-pulse`: Loading states
- `animate-spin-slow`: Scanning indicators
- Typewriter effect in terminal (custom `useEffect` loop)

### Path Aliases

Configured in both `tsconfig.json` and `vite.config.ts`:
```typescript
'@/*' → './src/*'
```

Example:
```typescript
import { SecurityReport } from '@/types';
import { apiClient } from '@/lib/api/client';
```

## File Organization

```
securiscan-ai/
├── server/                                    # Backend (Express)
│   ├── index.ts                               # Server entry point
│   ├── config/
│   │   └── env.ts                             # Environment validation
│   ├── middleware/
│   │   ├── cors.ts                            # CORS configuration
│   │   ├── rate-limit.ts                      # Rate limiting (10/15min)
│   │   └── error-handler.ts                   # Centralized error handling
│   ├── services/
│   │   └── openrouter.service.ts              # OpenRouter API client + mock mode
│   ├── routes/
│   │   └── scan.routes.ts                     # POST /api/scan endpoint
│   └── utils/
│       └── url-validator.ts                   # SSRF protection
│
├── src/                                       # Frontend (React)
│   ├── main.tsx                               # React entry point
│   ├── app.tsx                                # Main app component
│   │
│   ├── config/
│   │   ├── constants.ts                       # App constants
│   │   └── api-endpoints.ts                   # API URLs
│   │
│   ├── types/                                 # TypeScript type definitions
│   │   ├── index.ts                           # Re-exports all types
│   │   ├── security-report.types.ts           # Report data structures
│   │   ├── scan.types.ts                      # ScanStatus enum
│   │   └── api.types.ts                       # API request/response types
│   │
│   ├── i18n/                                  # Internationalization
│   │   ├── index.ts                           # useTranslation hook + exports
│   │   ├── types.ts                           # Translation types
│   │   └── locales/
│   │       ├── tr.ts                          # Turkish translations
│   │       └── en.ts                          # English translations
│   │
│   ├── lib/                                   # Utilities and libraries
│   │   ├── api/
│   │   │   ├── client.ts                      # Axios wrapper with baseURL
│   │   │   └── error-handler.ts               # API error handling
│   │   └── utils/
│   │       ├── url-validator.ts               # Client-side validation (UI feedback)
│   │       ├── format.ts                      # String formatting utilities
│   │       └── storage.ts                     # localStorage helpers
│   │
│   ├── hooks/                                 # Custom React hooks
│   │   ├── use-scan.ts                        # Scan orchestration (MAIN HOOK)
│   │   └── use-payment.ts                     # Payment flow state
│   │
│   ├── services/                              # Backend API calls
│   │   └── scan.service.ts                    # analyzeUrl() function
│   │
│   ├── features/                              # Feature-based components
│   │   ├── scanner/
│   │   │   ├── components/
│   │   │   │   ├── scan-terminal.tsx          # Animated terminal
│   │   │   │   └── scan-input-form.tsx        # URL input form
│   │   │   └── constants/
│   │   │       └── terminal-sequences.ts      # TR_SEQUENCE, EN_SEQUENCE
│   │   │
│   │   ├── report/
│   │   │   ├── components/
│   │   │   │   ├── report-dashboard.tsx       # Main report container
│   │   │   │   ├── vulnerability-card.tsx     # Individual vuln display
│   │   │   │   ├── executive-briefing.tsx     # Score + critical findings
│   │   │   │   ├── action-plan-table.tsx      # Sortable action items
│   │   │   │   └── network-info-panel.tsx     # Network/SSL/headers
│   │   │   └── utils/
│   │   │       └── score-calculator.ts        # CVSS score calculations
│   │   │
│   │   └── paywall/
│   │       ├── components/
│   │       │   └── paywall-overlay.tsx        # Payment modal
│   │       └── hooks/
│   │           └── use-payment-flow.ts        # Payment state management
│   │
│   └── components/                            # Shared UI components
│       ├── layout/
│       │   ├── header.tsx                     # App header with language selector
│       │   └── footer.tsx                     # App footer
│       └── ui/
│           ├── button.tsx                     # Reusable button component
│           └── language-selector.tsx          # TR/EN toggle
│
├── .env.example                               # Environment template
├── .env.local                                 # Local environment (git-ignored)
├── package.json                               # Dependencies + scripts
├── tsconfig.json                              # TypeScript config (frontend)
├── tsconfig.server.json                       # TypeScript config (backend)
├── vite.config.ts                             # Vite config with proxy
├── tailwind.config.js                         # Tailwind CSS config
└── index.html                                 # HTML template
```

## Key Implementation Details

### Security Features

**1. API Key Protection**
- API keys stored **ONLY** in backend environment (`.env.local`)
- Never exposed to client bundle
- Vite config **does not** use `define` to inject environment variables
- Client communicates via `/api/*` proxy

**2. SSRF Prevention** (server/utils/url-validator.ts)
```typescript
// Blocks:
- localhost, 127.0.0.1
- Private IPs: 10.x.x.x, 192.168.x.x, 172.16-31.x.x
- Link-local: 169.254.x.x
- IPv6 private ranges: fc00::/7, fe80::/10
```

**3. Rate Limiting**
- 10 requests per 15 minutes per IP
- Configured in `server/middleware/rate-limit.ts`
- Returns `429 Too Many Requests` when exceeded

**4. Security Headers** (Helmet.js)
- Content Security Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)

### URL Validation Flow

**Client-side** (useScan hook):
1. Check if URL is empty
2. Validate URL format with regex
3. Auto-prepend `https://` if protocol missing
4. Display inline validation errors

**Server-side** (url-validator.ts):
1. Parse URL with `new URL()`
2. Check protocol is http/https
3. Block localhost and private IPs (SSRF protection)
4. Return boolean indicating safety

### Language Re-fetching

When language changes, the app re-fetches the report to localize all content:
```typescript
// src/app.tsx
useEffect(() => {
  if (report && status === 'COMPLETE') {
    analyzeUrl(report.targetUrl, lang).then(setReport).catch(console.error);
  }
}, [lang, report, status]);
```

This ensures vulnerability descriptions, remediation steps, and all text is translated.

### Terminal-Report Synchronization

Two-phase completion check ensures terminal animation finishes before showing report:

```typescript
// src/hooks/use-scan.ts
useEffect(() => {
  if (status === 'SCANNING' && isTerminalReady) {
    if (report) {
      setStatus('COMPLETE');  // Both conditions met
    } else if (error) {
      setStatus('ERROR');
    }
  }
}, [status, isTerminalReady, report, error]);
```

- Phase 1: `analyzeUrl()` completes → sets `report`
- Phase 2: Terminal animation completes → sets `isTerminalReady`
- Only when **both** are true → transition to `COMPLETE`

### Paywall Implementation

Report renders with CSS blur when not paid:
```jsx
<div className={`transition-all duration-700 ${!isPaid ? 'filter blur-xl opacity-40 pointer-events-none h-[80vh] overflow-hidden' : ''}`}>
  <ReportDashboard report={report} ... />
</div>
{!isPaid && <PaywallOverlay onUnlock={() => setIsPaid(true)} ... />}
```

**Note**: Data is not actually hidden, just visually obscured. This is a UI-only paywall for demonstration purposes.

### Mock Mode vs Production

**Mock Mode** (`OPENROUTER_API_KEY=PLACEHOLDER_API_KEY`):
- Backend returns predefined sample data
- Perfect for frontend development without API costs
- All vulnerability data is hardcoded examples

**Production Mode** (valid API key):
- Backend calls OpenRouter API
- Real AI-powered security analysis
- Response parsed and validated before returning

## Technology Stack

### Frontend
- **React 19** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool (fast HMR, optimized builds)
- **Tailwind CSS** - Utility-first styling
- **Lucide React** - Icon library
- **Axios** - HTTP client with interceptors
- **Recharts** - Data visualization (pie charts)

### Backend
- **Express.js** - Web framework
- **TypeScript** - Type safety
- **Axios** - OpenRouter API client
- **Helmet** - Security headers middleware
- **CORS** - Cross-origin resource sharing
- **Express Rate Limit** - Rate limiting middleware
- **dotenv** - Environment variable management

### Development Tools
- **tsx** - TypeScript execution for dev server
- **concurrently** - Run client + server simultaneously
- **TypeScript** - Compilation for both client and server

## Development Workflow

### Starting Development

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Set up environment**:
   ```bash
   cp .env.example .env.local
   # Edit .env.local with your OPENROUTER_API_KEY
   ```

3. **Start development servers**:
   ```bash
   npm run dev
   ```
   This runs:
   - Backend: `http://localhost:3001`
   - Frontend: `http://localhost:3000` (or next available port)

### Making Changes

**Backend changes** (server/):
- tsx watch automatically reloads server on file changes
- Check console for server logs and errors

**Frontend changes** (src/):
- Vite HMR updates browser instantly
- Check browser console for React errors

### Adding New Features

**New component**:
1. Create in appropriate feature folder: `src/features/{feature}/components/{component-name}.tsx`
2. Use kebab-case for filenames
3. Import and use in parent component

**New API endpoint**:
1. Add route in `server/routes/`
2. Import and mount in `server/index.ts`
3. Create corresponding service call in `src/services/`

**New translation**:
1. Add key to `src/i18n/locales/tr.ts`
2. Add same key to `src/i18n/locales/en.ts`
3. Use via `t.keyName` in components

## Common Patterns

### Custom Hook Pattern
```typescript
// src/hooks/use-scan.ts
export function useScan(lang: 'tr' | 'en') {
  const [state, setState] = useState(...);

  const doSomething = useCallback(() => {
    // logic here
  }, [dependencies]);

  return { state, doSomething };
}

// Usage in component:
const { state, doSomething } = useScan(lang);
```

### Service Layer Pattern
```typescript
// src/services/scan.service.ts
import { apiClient } from '../lib/api/client';

export async function analyzeUrl(url: string, lang: 'tr' | 'en') {
  const response = await apiClient.post('/scan', { url, lang });
  return response.data;
}
```

### Feature Component Pattern
```
features/
  └── scanner/
      ├── components/
      │   └── scan-terminal.tsx  # Main component
      ├── constants/
      │   └── terminal-sequences.ts  # Data/config
      └── hooks/
          └── use-terminal-animation.ts  # Logic
```

## Troubleshooting

### Port Already in Use
- Backend: Change `PORT` in `.env.local`
- Frontend: Vite will auto-select next available port

### API Key Errors
- Check `.env.local` exists and has `OPENROUTER_API_KEY`
- Use `PLACEHOLDER_API_KEY` for mock mode

### CORS Issues
- Ensure `CLIENT_URL` in `.env.local` matches frontend URL
- Check CORS middleware in `server/middleware/cors.ts`

### Build Errors
- Clear node_modules and reinstall: `rm -rf node_modules && npm install`
- Check TypeScript errors: `npx tsc --noEmit`

## Future Enhancements

- Real payment integration (Stripe/İyzico)
- Webhook support for long-running scans
- PDF report generation
- Scan history/dashboard
- Multi-target batch scanning
- Custom scan profiles/templates
