/**
 * AbuseIPDB.gs
 * Checks the originating IP address of the email against the AbuseIPDB database.
 *
 * AbuseIPDB is a community-driven database where security professionals report
 * IP addresses involved in spam, phishing, brute force attacks, and botnets.
 * The API returns a confidence score (0-100%) indicating how likely the IP is abusive.
 *
 * Weight in scoring model: 12 points
 *
 * API Docs: https://docs.abuseipdb.com/#check-endpoint
 * Free tier: 1000 requests/day
 */

var ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2';

/**
 * Checks the originating IP address of the email against AbuseIPDB.
 *
 * @param {string} ip - The originating public IP address extracted from email headers
 * @returns {{ score: number, explanations: Array }}
 */
function checkAbuseIPDB(ip ) {
  var apiKey = getAbuseIPDBKey();

  // If no IP was found in the headers or no API key, skip gracefully
  if (!apiKey || !ip) {
    Logger.log('AbuseIPDB: No IP address found or no API key. Skipping.');
    return { score: 0, explanations: [] };
  }

  try {
    var response = UrlFetchApp.fetch(
      ABUSEIPDB_BASE_URL + '/check?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90&verbose',
      {
        method: 'get',
        headers: {
          'Key': apiKey,
          'Accept': 'application/json'
        },
        muteHttpExceptions: true
      }
    );

    var responseCode = response.getResponseCode();
    if (responseCode !== 200) {
      Logger.log('AbuseIPDB API error: HTTP ' + responseCode);
      return { score: 0, explanations: [] };
    }

    var data = JSON.parse(response.getContentText()).data;

    var confidenceScore = data.abuseConfidenceScore || 0;  // 0-100%
    var totalReports    = data.totalReports || 0;
    var countryCode     = data.countryCode || 'Unknown';
    var isp             = data.isp || 'Unknown ISP';
    var usageType       = data.usageType || '';

    // Only flag if confidence score is above a meaningful threshold
    // Low scores (< 20%) are likely false positives from shared hosting IPs
    if (confidenceScore < 20) {
      return { score: 0, explanations: [] };
    }

    // Map confidence score (0-100%) to our weight (max 12 points)
    // confidence 20-50%  → low score
    // confidence 51-80%  → medium score
    // confidence 81-100% → full score
    var ratio = confidenceScore / 100;
    var contributedScore = Math.round(WEIGHTS.ABUSEIPDB * ratio);

    // Build a human-readable detail string
    var details = 'Originating IP ' + ip + ' has an abuse confidence score of ' +
                  confidenceScore + '% (' + totalReports + ' reports, ' +
                  countryCode + ', ' + isp + ').';

    // Add usage type if it reveals something suspicious (e.g., "Data Center/Web Hosting")
    if (usageType) {
      details += ' Usage type: ' + usageType + '.';
    }

    return {
      score: contributedScore,
      explanations: [{
        signal: 'AbuseIPDB: Reported IP',
        details: details,
        weight: contributedScore
      }]
    };

  } catch (err) {
    Logger.log('AbuseIPDB error: ' + err.message);
    return { score: 0, explanations: [] };
  }
}
