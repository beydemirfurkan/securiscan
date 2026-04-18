<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# SecuriScan AI

**Advanced web security vulnerability scanner** with real-time analysis, comprehensive reporting, and multi-language support.

## Features

### Core Scanning
- **Comprehensive Analysis**: 15+ modular security scanners covering OWASP Top 10
- **Real-time Terminal Interface**: Interactive terminal-style scanning experience
- **Multi-language Support**: Full Turkish and English localization
- **Secure Architecture**: Backend API with SSRF protection, rate limiting, and security headers

### Security Scanners
- **SSL/TLS Scanner**: Certificate validation, protocol analysis, and grade scoring
- **Header Scanner**: Security header analysis (CSP, HSTS, X-Frame-Options, etc.)
- **Port Scanner**: Open port detection with service identification
- **Technology Detector**: Framework and library detection with version info
- **DNS Scanner**: DNS record analysis and subdomain enumeration
- **Cookie Analyzer**: Cookie security flags validation (HttpOnly, Secure, SameSite)

### Advanced Vulnerability Detection
- **CORS Misconfiguration**: Detects wildcard origins, credential leaks, and reflected origins
- **Directory Traversal**: Tests path traversal patterns (../, ..%2f, etc.)
- **Open Redirect**: Identifies URL parameters vulnerable to redirect attacks
- **HTTP Methods**: Detects dangerous methods (PUT, DELETE, TRACE)
- **Robots.txt Analysis**: Extracts sensitive paths and admin panels
- **Security.txt Check**: Validates security contact information presence
- **CVE Correlation**: Maps detected technologies to known vulnerabilities
- **Active Scanning**: SQLi, XSS, and sensitive file detection

### Reporting & Export
- **PDF Reports**: Professional reports with executive summary, vulnerability tables, and action plans
- **JSON Export**: Machine-readable format for automation and integration
- **CVSS Scoring**: Industry-standard vulnerability severity ratings
- **Remediation Steps**: Actionable fix recommendations for each finding
- **Compliance Checks**: OWASP, PCI-DSS, and GDPR compliance status

## Architecture

### Backend (Express.js 5)
- **Server**: Express on port 3001
- **Security**: Helmet, CORS, rate limiting (10 req/15min), SSRF protection
- **Scanners**: Modular scanner architecture with 15+ security modules
- **Services**: GeoIP, WHOIS, scan progress (SSE)

### Frontend (React + Vite)
- **Framework**: React 19 with TypeScript
- **Build Tool**: Vite with hot module replacement
- **Styling**: Tailwind CSS with custom cyber theme
- **Charts**: Recharts for vulnerability distribution visualization
- **PDF Generation**: jsPDF with auto-table for report export
- **State Management**: Custom hooks pattern
- **i18n**: Centralized translation management

## Project Structure

```
securiscan-ai/
├── server/                          # Express backend
│   ├── config/                      # Environment configuration
│   ├── middleware/                   # CORS, rate limiting, error handling
│   ├── services/                    # GeoIP, WHOIS, scan progress
│   ├── routes/                      # API endpoints
│   ├── scanners/                    # Security scanner modules
│   │   ├── ssl-scanner.ts
│   │   ├── header-scanner.ts
│   │   ├── port-scanner.ts
│   │   ├── dns-scanner.ts
│   │   ├── tech-detector.ts
│   │   ├── active-scanner.ts
│   │   ├── http-methods-scanner.ts
│   │   ├── robots-scanner.ts
│   │   ├── cve-correlator.ts
│   │   ├── vulnerability-detector.ts
│   │   ├── scoring-engine.ts
│   │   ├── content-analyzer.ts
│   │   ├── compliance-checker.ts
│   │   └── action-plan-generator.ts
│   └── utils/                       # URL validator, ports, constants
│
└── src/                             # React frontend
    ├── config/                      # App constants and API endpoints
    ├── types/                       # TypeScript type definitions
    ├── i18n/                        # Translations (tr/en)
    ├── lib/                         # API client and utilities
    ├── hooks/                       # Custom React hooks
    ├── services/                    # Backend API calls, PDF/JSON export
    ├── features/                    # Feature-based components
    │   ├── scanner/                 # Scan terminal and input
    │   └── report/                  # Dashboard and vulnerability cards
    └── components/                  # Shared UI components
```

## Setup

### Prerequisites
- Node.js 18+ and npm

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/beydemirfurkan/securiscan.git
   cd securiscan
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**

   Create a `.env.local` file in the project root:
   ```bash
   PORT=3001
   NODE_ENV=development
   CLIENT_URL=http://localhost:3000
   ```

4. **Run the application**

   **Development mode** (starts both backend and frontend):
   ```bash
   npm run dev
   ```

   Or run separately:
   ```bash
   # Terminal 1: Backend
   npm run dev:server

   # Terminal 2: Frontend
   npm run dev:client
   ```

5. **Access the application**
   - Frontend: http://localhost:3000 (or auto-assigned port)
   - Backend API: http://localhost:3001

## Security Features

### Backend Security
- **SSRF Prevention**: Blocks localhost and private IP scanning
- **Rate Limiting**: 10 requests per 15 minutes per IP
- **Security Headers**: Helmet.js for HTTP security headers
- **CORS**: Configured for allowed origins
- **Input Validation**: Server-side URL validation
- **No Secrets in Bundle**: API keys stay server-side only

### Scanning Capabilities
| Scanner | Description | Severity Range |
|---------|-------------|----------------|
| SSL/TLS | Certificate and protocol analysis | INFO - CRITICAL |
| Headers | Security header validation | LOW - HIGH |
| CORS | Cross-origin misconfiguration | MEDIUM - CRITICAL |
| Directory Traversal | Path traversal vulnerabilities | CRITICAL |
| Open Redirect | URL redirect vulnerabilities | MEDIUM |
| HTTP Methods | Dangerous method detection | MEDIUM - HIGH |
| Active Scanner | SQLi, XSS, sensitive files | MEDIUM - CRITICAL |
| CVE Correlation | Known vulnerability mapping | LOW - CRITICAL |

## Testing

Run the test suite:
```bash
npm test
```

The project includes 79+ tests covering:
- HTTP Methods Scanner (property-based tests)
- Active Scanner (CORS, traversal, redirect)
- CVE Correlator (version matching, sorting)
- Robots Scanner (parsing, sensitive path detection)
- Report Exporter (JSON round-trip, filename generation)

## Build & Deployment

### Build for production
```bash
npm run build
```

This creates:
- `dist/` - Client static files
- `dist/server/` - Compiled backend code

### Deployment Options

**Backend**: Deploy to any Node.js platform
- Railway, Render, Fly.io, Heroku
- Set environment variables in platform settings

**Frontend**: Deploy static build to
- Vercel, Netlify, Cloudflare Pages
- Configure API proxy to backend URL

## Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Run both backend and frontend concurrently |
| `npm run dev:client` | Run frontend only (Vite dev server) |
| `npm run dev:server` | Run backend only (Express server) |
| `npm run build` | Build both client and server for production |
| `npm run build:server` | Build server only (TypeScript compilation) |
| `npm test` | Run test suite with Vitest |

## Technology Stack

### Frontend
- **React 19** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool and dev server
- **Tailwind CSS** - Utility-first CSS
- **Recharts** - Data visualization
- **jsPDF** - PDF generation
- **Lucide React** - Icon library
- **Axios** - HTTP client

### Backend
- **Express.js 5** - Web framework
- **TypeScript** - Type safety
- **Axios** - HTTP client for scanning
- **Helmet** - Security headers
- **CORS** - Cross-origin configuration
- **Express Rate Limit** - Rate limiting

### Testing
- **Vitest** - Test runner
- **fast-check** - Property-based testing

## Contributing

Contributions are welcome! Please ensure:
- Kebab-case file naming
- TypeScript types for all code
- Security best practices
- Modular component structure
- Tests for new scanners

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
