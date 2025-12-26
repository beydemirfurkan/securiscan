<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# SecuriScan AI V4

**Advanced AI-powered security vulnerability scanner** with real-time analysis, comprehensive reporting, and multi-language support.

## 🚀 Features

- **AI-Powered Analysis**: Leverages Google Gemini 3 Flash via OpenRouter for intelligent security scanning
- **Real-time Terminal Interface**: Interactive terminal-style scanning experience
- **Comprehensive Reports**: Detailed vulnerability reports with CVSS scoring, exploit chains, and remediation steps
- **Multi-language Support**: Full Turkish and English localization
- **Secure Architecture**: Backend API with SSRF protection, rate limiting, and security headers
- **Modular Design**: Feature-based organization with kebab-case naming conventions

## 🏗️ Architecture

### Backend (Express.js)
- **Server**: Express on port 3001
- **API Integration**: OpenRouter (Google Gemini Flash model)
- **Security**: Helmet, CORS, rate limiting (10 req/15min), SSRF protection
- **Mock Mode**: Development mode with sample data when API key not configured

### Frontend (React + Vite)
- **Framework**: React 19 with TypeScript
- **Build Tool**: Vite with hot module replacement
- **Styling**: Tailwind CSS with custom cyber theme
- **State Management**: Custom hooks pattern
- **i18n**: Centralized translation management

## 📁 Project Structure

```
securiscan-ai/
├── server/                          # Express backend
│   ├── config/                      # Environment configuration
│   ├── middleware/                  # CORS, rate limiting, error handling
│   ├── services/                    # OpenRouter API integration
│   ├── routes/                      # API endpoints
│   └── utils/                       # URL validator (SSRF protection)
│
└── src/                             # React frontend
    ├── config/                      # App constants and API endpoints
    ├── types/                       # TypeScript type definitions
    ├── i18n/                        # Translations (tr/en)
    ├── lib/                         # API client and utilities
    ├── hooks/                       # Custom React hooks
    ├── services/                    # Backend API calls
    ├── features/                    # Feature-based components
    │   ├── scanner/                 # Scan terminal and input
    │   ├── report/                  # Dashboard and vulnerability cards
    │   └── paywall/                 # Payment overlay (structure only)
    └── components/                  # Shared UI components
```

## 🛠️ Setup Instructions

### Prerequisites
- Node.js 18+ and npm
- OpenRouter API key (or use mock mode for development)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd securiscan-ai
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**

   Create `.env.local` from the example:
   ```bash
   cp .env.example .env.local
   ```

   Edit `.env.local` and set your OpenRouter API key:
   ```bash
   OPENROUTER_API_KEY=sk-or-v1-your_api_key_here
   PORT=3001
   NODE_ENV=development
   CLIENT_URL=http://localhost:3000
   ```

   **Note**: If you don't have an API key, the app will run in **mock mode** with sample data.

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

## 🔒 Security Features

### Backend Security
- **API Key Protection**: API keys never exposed to client bundle
- **SSRF Prevention**: Blocks localhost and private IP scanning
- **Rate Limiting**: 10 requests per 15 minutes per IP
- **Security Headers**: Helmet.js for HTTP security headers
- **CORS**: Configured for localhost development
- **Input Validation**: Server-side URL validation

### Code Security
- No environment variables in client bundle
- Secure API communication via proxy
- TypeScript for type safety
- Modular architecture for maintainability

## 📦 Build & Deployment

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

## 🌐 Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Run both backend and frontend concurrently |
| `npm run dev:client` | Run frontend only (Vite dev server) |
| `npm run dev:server` | Run backend only (Express server) |
| `npm run build` | Build both client and server for production |
| `npm run build:server` | Build server only (TypeScript compilation) |

## 🧩 Technology Stack

### Frontend
- **React 19** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool and dev server
- **Tailwind CSS** - Utility-first CSS
- **Lucide React** - Icon library
- **Axios** - HTTP client

### Backend
- **Express.js** - Web framework
- **TypeScript** - Type safety
- **Axios** - OpenRouter API client
- **Helmet** - Security headers
- **CORS** - Cross-origin configuration
- **Express Rate Limit** - Rate limiting

## 📝 Development Notes

### Mock Mode
When `OPENROUTER_API_KEY=PLACEHOLDER_API_KEY` in `.env.local`, the app runs in mock mode with sample vulnerability data. Perfect for:
- Frontend development
- UI testing
- Demo purposes

### OpenRouter Integration
The app uses **google/gemini-flash-1.5-8b** model via OpenRouter. To use a different model, edit:
```typescript
// server/services/openrouter.service.ts
model: 'your-preferred-model'
```

### Adding New Languages
1. Create new locale file: `src/i18n/locales/{lang}.ts`
2. Add to translations export in `src/i18n/index.ts`
3. Update `Language` type in `src/i18n/types.ts`

## 🐛 Troubleshooting

### Port Already in Use
If port 3001 is busy, change `PORT` in `.env.local`:
```bash
PORT=3002
```

### API Key Error
Ensure `.env.local` exists and contains valid `OPENROUTER_API_KEY`. For development without API key, use:
```bash
OPENROUTER_API_KEY=PLACEHOLDER_API_KEY
```

### CORS Issues
Check `CLIENT_URL` in `.env.local` matches your frontend URL.

## 📄 License

This project is licensed under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Kebab-case file naming
- TypeScript types for all code
- Security best practices
- Modular component structure

---

**SECURISCAN ENGINE v4.0.2 // STABLE RELEASE**
© 2025 GLOBAL DEFENSE SYSTEMS
