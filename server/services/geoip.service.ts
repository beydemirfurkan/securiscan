/**
 * GeoIP Service
 * Provides IP geolocation, ISP, and ASN information
 * Uses ip-api.com (free tier: 45 requests/minute)
 */

import axios from 'axios';

export interface GeoIPInfo {
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  regionName: string;
  city: string;
  zip: string;
  lat: number;
  lon: number;
  timezone: string;
  isp: string;
  org: string;
  as: string; // ASN
  asname: string;
}

const IP_API_URL = 'http://ip-api.com/json';

/**
 * Get geolocation and ISP information for an IP address
 * @param ip - IP address to lookup
 * @returns GeoIP information or null if lookup fails
 */
export async function getGeoIP(ip: string): Promise<GeoIPInfo | null> {
  try {
    const response = await axios.get<any>(`${IP_API_URL}/${ip}`, {
      params: {
        fields: 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname',
      },
      timeout: 5000,
    });

    if (response.data.status === 'fail') {
      console.error('[GeoIP] Lookup failed:', response.data.message);
      return null;
    }

    return {
      ip,
      country: response.data.country || 'Unknown',
      countryCode: response.data.countryCode || '',
      region: response.data.region || '',
      regionName: response.data.regionName || '',
      city: response.data.city || '',
      zip: response.data.zip || '',
      lat: response.data.lat || 0,
      lon: response.data.lon || 0,
      timezone: response.data.timezone || '',
      isp: response.data.isp || 'Unknown',
      org: response.data.org || 'Unknown',
      as: response.data.as || 'Unknown',
      asname: response.data.asname || 'Unknown',
    };
  } catch (error: any) {
    console.error('[GeoIP] Error:', error.message);
    return null;
  }
}

/**
 * Format location string from GeoIP data
 */
export function formatLocation(geoip: GeoIPInfo | null, lang: 'tr' | 'en'): string {
  if (!geoip) {
    return lang === 'tr' ? 'Bilinmiyor' : 'Unknown';
  }

  const parts = [];
  if (geoip.city) parts.push(geoip.city);
  if (geoip.regionName) parts.push(geoip.regionName);
  if (geoip.country) parts.push(geoip.country);

  return parts.join(', ') || (lang === 'tr' ? 'Bilinmiyor' : 'Unknown');
}
