/**
 * SafeBrowsing.gs
 * Checks URLs found in the email against Google's Safe Browsing API.
 *
 * Google Safe Browsing maintains a constantly updated blacklist of URLs
 * known to host phishing pages, malware, and unwanted software.
 * It's the same database used by Chrome to show "Dangerous site" warnings.
 *
 * Weight in scoring model: 3 points (binary signal — either flagged or not)
 *
 * API Docs: https://developers.google.com/safe-browsing/v4/lookup-api
 * Free tier: 10,000 requests/day
 */

var SAFE_BROWSING_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

/**
 * Checks a list of URLs against Google Safe Browsing's threat database.
 *
 * @param {Array} urls - Array of URLs extracted from the email body
 * @returns {{ score: number, explanations: Array }}
 */
function checkSafeBrowsing(urls ) {
  var apiKey = getSafeBrowsingKey();

  if (!apiKey || !urls || urls.length === 0) {
    return { score: 0, explanations: [] };
  }

  // Limit to first 10 URLs — Safe Browsing allows up to 500 per request
  // but we keep it small to stay within free tier comfortably
  var urlsToCheck = urls.slice(0, 10);

  // Build the URL entries array in the format the API expects
  var urlEntries = urlsToCheck.map(function(url) {
    return { url: url };
  });

  try {
    var response = UrlFetchApp.fetch(SAFE_BROWSING_URL + '?key=' + apiKey, {
      method: 'post',
      contentType: 'application/json',
      muteHttpExceptions: true,
      payload: JSON.stringify({
        client: {
          clientId:      'gmail-malicious-email-scorer',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          // Check for all major threat types
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',   // Phishing
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION'
          ],
          platformTypes:    ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries:    urlEntries
        }
      })
    });

    var responseCode = response.getResponseCode();
    if (responseCode !== 200) {
      Logger.log('Safe Browsing API error: HTTP ' + responseCode);
      return { score: 0, explanations: [] };
    }

    var data = JSON.parse(response.getContentText());

    // If the response body is empty, no threats were found — this is the normal safe case
    if (!data.matches || data.matches.length === 0) {
      return { score: 0, explanations: [] };
    }

    // At least one URL was found in Google's threat database
    var threatTypes = data.matches.map(function(m) {
      return m.threatType.replace(/_/g, ' ').toLowerCase();
    });

    // Remove duplicates
    var uniqueThreats = threatTypes.filter(function(v, i, a) {
      return a.indexOf(v) === i;
    });

    var flaggedUrl = data.matches[0].threat.url;
    var shortUrl = flaggedUrl.length > 60 ? flaggedUrl.substring(0, 57) + '...' : flaggedUrl;

    return {
      score: WEIGHTS.SAFE_BROWSING,
      explanations: [{
        signal: 'Google Safe Browsing: Threat Detected',
        details: 'URL flagged by Google Safe Browsing for: ' + uniqueThreats.join(', ') +
                 '. URL: ' + shortUrl,
        weight: WEIGHTS.SAFE_BROWSING
      }]
    };

  } catch (err) {
    Logger.log('Safe Browsing error: ' + err.message);
    return { score: 0, explanations: [] };
  }
}
