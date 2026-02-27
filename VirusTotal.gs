/**
 * VirusTotal.gs
 * Checks domain and URL reputation using the VirusTotal API v3.
 *
 * VirusTotal aggregates results from 70+ antivirus engines and security vendors.
 * A domain or URL flagged by even a few engines is a strong indicator of malice.
 *
 * Weight in scoring model: 15 points
 *
 * API Docs: https://developers.virustotal.com/reference/overview
 * Free tier: 500 requests/day, 4 requests/minute (enough for a user) if I get more than 500 
 * I get an error 429 and return 0
 */

var VT_BASE_URL = 'https://www.virustotal.com/api/v3'; // in case URL changes 

/**
 * Checks the sender's domain and any URLs found in the email against VirusTotal.
 *
 * @param {string} domain - The sender's domain (e.g., "paypal-update.ru" )
 * @param {Array}  urls   - Array of URLs extracted from the email body
 * @returns {{ score: number, explanations: Array }}
 */
function checkVirusTotal(domain, urls) {
  var apiKey = getVirusTotalKey(); // from scriptproperties

  if (!apiKey || !domain) {
    return { score: 0, explanations: [] };
  }

  var score = 0;
  var explanations = [];

  // --- Check the sender's domain ---
  try {
    var domainResult = vtCheckDomain(domain, apiKey);
    if (domainResult.malicious > 0 || domainResult.suspicious > 0) {
      // Scale: 1-2 engines = half weight, 3+ engines = full weight (1)
      var ratio = Math.min((domainResult.malicious + domainResult.suspicious) / 3, 1);
      var domainScore = Math.round(WEIGHTS.VIRUSTOTAL * 0.7 * ratio); // Domain gets 70% of VT weight
      // bc if the domain is suspicious it's a higher indicator
      score += domainScore;
      explanations.push({ // for the user 
        signal: 'VirusTotal: Malicious Domain',
        details: 'Domain ' + domain + ' flagged by ' + domainResult.malicious + ' malicious and ' +
                 domainResult.suspicious + ' suspicious engines out of ' + domainResult.total + '.',
        weight: domainScore
      });
    }
  } catch (err) {
    Logger.log('VirusTotal domain check error: ' + err.message);
  }

  // --- Check URLs found in the email body ---
  // Only check the first 3 URLs to avoid hitting rate limits
  var urlsToCheck = (urls || []).slice(0, 3);

  for (var i = 0; i < urlsToCheck.length; i++) {
    try {
      var urlResult = vtCheckUrl(urlsToCheck[i], apiKey);
      if (urlResult.malicious > 0 || urlResult.suspicious > 0) {
        var urlRatio = Math.min((urlResult.malicious + urlResult.suspicious) / 3, 1);
        var urlScore = Math.round(WEIGHTS.VIRUSTOTAL * 0.3 * urlRatio); // URLs get 30% of VT weight
        score += urlScore;
        explanations.push({
          signal: 'VirusTotal: Malicious URL',
          details: 'URL flagged by ' + urlResult.malicious + ' malicious engines: ' +
                   urlsToCheck[i].substring(0, 60) + (urlsToCheck[i].length > 60 ? '...' : ''),
          weight: urlScore
        });
        break; // One flagged URL is enough — stop checking to save API quota
      }
    } catch (err) { // avoid VT to crash we continue for the next check
      Logger.log('VirusTotal URL check error for ' + urlsToCheck[i] + ': ' + err.message);
    }
  }

  return { score: Math.min(score, WEIGHTS.VIRUSTOTAL), explanations: explanations };
}

/**
 * Calls VirusTotal API for a domain's reputation.
 * Returns how many engines said: malicious, suspicious, and total engines checked.
 * VirusTotal requires the API key in the request headers 
 * @param {string} domain - Domain to check
 * @param {string} apiKey - VirusTotal API key
 * @returns {{ malicious: number, suspicious: number, total: number }}
 */
function vtCheckDomain(domain, apiKey) {
  var response = UrlFetchApp.fetch(VT_BASE_URL + '/domains/' + encodeURIComponent(domain), {
    method: 'get', // only read
    headers: { 'x-apikey': apiKey },// VT authenticates differently from Gemini
    muteHttpExceptions: true // if vt returns 429 or 500 apps script we handle with the problem
  });

  if (response.getResponseCode() !== 200) {
    Logger.log('VirusTotal domain API error: HTTP ' + response.getResponseCode());
    return { malicious: 0, suspicious: 0, total: 0 }; // just get 0 if we got an error
  }

  var data = JSON.parse(response.getContentText()); // parse to js
  var stats = data.data.attributes.last_analysis_stats; // dig into vt to get stats

  return {
    malicious:  stats.malicious  || 0,
    suspicious: stats.suspicious || 0,
    total: (stats.malicious || 0) + (stats.suspicious || 0) +
           (stats.harmless || 0) + (stats.undetected || 0)
  };
}

/**
 * Queries the VirusTotal API for a URL's reputation.
 * VirusTotal requires URLs to be base64-encoded (without padding) for the v3 API.
 *
 * @param {string} url    - URL to check
 * @param {string} apiKey - VirusTotal API key
 * @returns {{ malicious: number, suspicious: number, total: number }}
 */
function vtCheckUrl(url, apiKey) { // this is for the URl 
 // VirusTotal requires URLs to be encoded before sending - special characters like / and ? would break the request
  var urlId = Utilities.base64EncodeWebSafe(url).replace(/=+$/, '');

  var response = UrlFetchApp.fetch(VT_BASE_URL + '/urls/' + urlId, {
    method: 'get',// http for just reading
    headers: { 'x-apikey': apiKey },
    muteHttpExceptions: true
  });

  if (response.getResponseCode() !== 200) {
    Logger.log('VirusTotal URL API error: HTTP ' + response.getResponseCode());
    return { malicious: 0, suspicious: 0, total: 0 };
  }

  var data = JSON.parse(response.getContentText());
  var stats = data.data.attributes.last_analysis_stats;

  return {
    malicious:  stats.malicious  || 0,
    suspicious: stats.suspicious || 0,
    total: (stats.malicious || 0) + (stats.suspicious || 0) +
           (stats.harmless || 0) + (stats.undetected || 0)
  };
}
