/**
 * IPQualityScore.gs
 * Checks the sender's email address for fraud signals using IPQualityScore API.
 *
 * Unlike VirusTotal (which checks domains/URLs) and AbuseIPDB (which checks IPs),
 * IPQualityScore specializes in EMAIL ADDRESS validation — it detects:
 * - Disposable/temporary email addresses (e.g., mailinator.com, guerrillamail.com)
 * - Known fraudulent email addresses
 * - Recently created domains used for phishing campaigns
 * - Invalid or non-existent email addresses
 *
 * Weight in scoring model: 8 points
 *
 * API Docs: https://www.ipqualityscore.com/documentation/email-validation/overview
 * Free tier: 200 requests/day
 */

var IPQS_BASE_URL = 'https://ipqualityscore.com/api/json/email';

/**
 * Checks the sender's email address against IPQualityScore's fraud database.
 *
 * @param {string} email - The sender's full email address (e.g., "user@domain.com" )
 * @returns {{ score: number, explanations: Array }}
 */
function checkIPQualityScore(email) {
  var apiKey = getIPQualityScoreKey();

  if (!apiKey || !email) {
    return { score: 0, explanations: [] };
  }

  try {
    var response = UrlFetchApp.fetch(
      IPQS_BASE_URL + '/' + apiKey + '/' + encodeURIComponent(email) + '?strictness=1&abuse_strictness=1',
      {
        method: 'get',
        muteHttpExceptions: true
      }
    );

    var responseCode = response.getResponseCode();
    if (responseCode !== 200) {
      Logger.log('IPQualityScore API error: HTTP ' + responseCode);
      return { score: 0, explanations: [] };
    }

    var data = JSON.parse(response.getContentText());

    // API returns success: false if the request itself failed
    if (!data.success) {
      Logger.log('IPQualityScore API returned error: ' + (data.message || 'Unknown error'));
      return { score: 0, explanations: [] };
    }

    var score = 0;
    var flags = [];

    // --- Disposable email address ---
    // Temporary email services are almost exclusively used for fraud and spam
    if (data.disposable) {
      score += Math.round(WEIGHTS.IPQUALITYSCORE * 0.6); // 60% of weight
      flags.push('disposable email address');
    }

    // --- Known fraudulent email ---
    // Directly reported as used in fraud campaigns
    if (data.fraud_score && data.fraud_score >= 75) {
      score += Math.round(WEIGHTS.IPQUALITYSCORE * 0.5); // 50% of weight
      flags.push('fraud score ' + data.fraud_score + '/100');
    }

    // --- Recently created domain ---
    // Domains created less than 180 days ago are commonly used in phishing campaigns
    if (data.domain_age && data.domain_age.days !== undefined && data.domain_age.days < 180) {
      score += Math.round(WEIGHTS.IPQUALITYSCORE * 0.3); // 30% of weight
      flags.push('domain created only ' + data.domain_age.days + ' days ago');
    }

    // --- DNS/MX record issues ---
    // A domain with no valid mail server is a strong indicator of a fake domain
    if (data.dns_valid === false) {
      score += Math.round(WEIGHTS.IPQUALITYSCORE * 0.4); // 40% of weight
      flags.push('invalid DNS / no mail server found');
    }

    // Cap at the maximum weight for this signal
    score = Math.min(score, WEIGHTS.IPQUALITYSCORE);

    if (score === 0 || flags.length === 0) {
      return { score: 0, explanations: [] };
    }

    return {
      score: score,
      explanations: [{
        signal: 'IPQualityScore: Suspicious Email',
        details: 'Sender email ' + email + ' flagged for: ' + flags.join(', ') + '.',
        weight: score
      }]
    };

  } catch (err) {
    Logger.log('IPQualityScore error: ' + err.message);
    return { score: 0, explanations: [] };
  }
}
