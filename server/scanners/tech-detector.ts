/**
 * Technology Stack Detector
 * Identifies web technologies, frameworks, and CMS from headers and HTML
 */

import axios from 'axios';
import {
  CMS_SIGNATURES,
  FRAMEWORK_SIGNATURES,
  VULNERABLE_VERSIONS,
} from '../utils/security-constants';

export interface TechStackItem {
  name: string;
  description: string;
  commonRisks: Array<{ name: string }>;
}

/**
 * Detect technology stack from headers and HTML content
 * @param url - The URL to analyze
 * @param headers - HTTP response headers as key-value object
 * @returns Array of detected technologies
 */
export async function detectTechStack(
  url: string,
  headers: Record<string, string>
): Promise<TechStackItem[]> {
  const techStack: TechStackItem[] = [];
  const detectedTechs = new Set<string>();

  // 1. Detect from Server header
  if (headers['server']) {
    const serverInfo = parseServerHeader(headers['server']);
    if (serverInfo && !detectedTechs.has(serverInfo.name)) {
      detectedTechs.add(serverInfo.name);
      techStack.push(serverInfo);
    }
  }

  // 2. Detect from X-Powered-By header
  if (headers['x-powered-by']) {
    const poweredBy = headers['x-powered-by'];
    if (!detectedTechs.has(poweredBy)) {
      detectedTechs.add(poweredBy);

      techStack.push({
        name: poweredBy,
        description: 'Backend Technology',
        commonRisks: getVersionRisks('php', poweredBy) || [],
      });
    }
  }

  // 3. Detect from HTML content
  try {
    const response = await axios.get(url, {
      timeout: 10000,
      maxContentLength: 100000, // Limit to 100KB
      validateStatus: () => true,
    });

    const html = response.data;

    // Detect CMS
    Object.entries(CMS_SIGNATURES).forEach(([cms, signatures]) => {
      if (signatures.some((sig) => html.includes(sig)) && !detectedTechs.has(cms)) {
        detectedTechs.add(cms);

        techStack.push({
          name: cms,
          description: 'Content Management System',
          commonRisks: getVersionRisks('wordpress', cms.toLowerCase()) || [
            { name: 'Plugin vulnerabilities common in CMS platforms' },
          ],
        });
      }
    });

    // Detect Frameworks
    Object.entries(FRAMEWORK_SIGNATURES).forEach(([framework, signatures]) => {
      if (signatures.some((sig) => html.includes(sig)) && !detectedTechs.has(framework)) {
        detectedTechs.add(framework);

        techStack.push({
          name: framework,
          description: 'Frontend Framework/Library',
          commonRisks: [{ name: 'Ensure framework is up to date' }],
        });
      }
    });

    // Detect from meta tags
    const metaTags = extractMetaTags(html);
    metaTags.forEach((tech) => {
      if (!detectedTechs.has(tech.name)) {
        detectedTechs.add(tech.name);
        techStack.push(tech);
      }
    });

  } catch (error: any) {
    // HTML fetching failed, that's okay - we have header-based detection
    console.log(`[TechDetector] HTML fetch failed: ${error.message}`);
  }

  // 4. Detect from cookies
  if (headers['set-cookie']) {
    const cookieTechs = detectFromCookies(headers['set-cookie']);
    cookieTechs.forEach((tech) => {
      if (!detectedTechs.has(tech.name)) {
        detectedTechs.add(tech.name);
        techStack.push(tech);
      }
    });
  }

  return techStack;
}

/**
 * Parse Server header to extract web server name and version
 */
function parseServerHeader(serverHeader: string): TechStackItem | null {
  const patterns = [
    { regex: /(nginx)\/?([\d.]+)?/i, name: 'nginx' },
    { regex: /(apache)\/?([\d.]+)?/i, name: 'apache' },
    { regex: /(microsoft-iis)\/?([\d.]+)?/i, name: 'iis' },
    { regex: /(cloudflare)/i, name: 'cloudflare' },
    { regex: /(litespeed)/i, name: 'litespeed' },
  ];

  for (const pattern of patterns) {
    const match = serverHeader.match(pattern.regex);
    if (match) {
      const [, name, version] = match;
      const normalizedName = name.toLowerCase();
      const risks = version ? getVersionRisks(normalizedName, version) : [];

      return {
        name: version ? `${name} ${version}` : name,
        description: 'Web Server',
        commonRisks: risks || [{ name: 'Ensure server is up to date' }],
      };
    }
  }

  return null;
}

/**
 * Get known vulnerabilities for a specific technology version
 */
function getVersionRisks(tech: string, version: string): Array<{ name: string }> | null {
  const techData = VULNERABLE_VERSIONS[tech.toLowerCase()];
  if (!techData) return null;

  const versionData = techData[version];
  if (!versionData) return null;

  return versionData.map((cve) => ({ name: cve }));
}

/**
 * Extract technology information from HTML meta tags
 */
function extractMetaTags(html: string): TechStackItem[] {
  const techs: TechStackItem[] = [];

  // Generator meta tag
  const generatorMatch = html.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
  if (generatorMatch) {
    techs.push({
      name: generatorMatch[1],
      description: 'Detected from Generator Meta Tag',
      commonRisks: [],
    });
  }

  // Application name
  const appNameMatch = html.match(/<meta\s+name=["']application-name["']\s+content=["']([^"']+)["']/i);
  if (appNameMatch) {
    techs.push({
      name: appNameMatch[1],
      description: 'Application Name',
      commonRisks: [],
    });
  }

  return techs;
}

/**
 * Detect technology from cookies
 */
function detectFromCookies(setCookie: string | string[]): TechStackItem[] {
  const techs: TechStackItem[] = [];
  const cookies = Array.isArray(setCookie) ? setCookie.join(';') : setCookie;

  const cookiePatterns: Record<string, string> = {
    'PHPSESSID': 'PHP',
    'ASP.NET_SessionId': 'ASP.NET',
    'JSESSIONID': 'Java/JSP',
    'laravel_session': 'Laravel',
    'csrftoken': 'Django',
    'connect.sid': 'Express.js',
    'ci_session': 'CodeIgniter',
  };

  Object.entries(cookiePatterns).forEach(([cookieName, techName]) => {
    if (cookies.includes(cookieName)) {
      techs.push({
        name: techName,
        description: 'Detected from Session Cookie',
        commonRisks: [{ name: 'Session management vulnerabilities possible' }],
      });
    }
  });

  return techs;
}
