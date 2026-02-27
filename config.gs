/**
 * Config.gs
 * Securely stores and retrieves API keys using Apps Script's Properties Service.
 * Keys are never hardcoded in the source code — they live in Google's secure storage.
 */

// -------------------------------------------------------
// SETUP FUNCTION — Run this ONCE manually to store your keys
// -------------------------------------------------------
function setApiKeys() {
  var props = PropertiesService.getScriptProperties();
  props.setProperties({
    'VIRUSTOTAL_API_KEY':     'YOUR_VIRUSTOTAL_KEY_HERE',
    'ABUSEIPDB_API_KEY':      'YOUR_ABUSEIPDB_KEY_HERE',
    'IPQUALITYSCORE_API_KEY': 'YOUR_IPQUALITYSCORE_KEY_HERE',
    'SAFEBROWSING_API_KEY':   'YOUR_SAFEBROWSING_KEY_HERE',
    'GEMINI_API_KEY':         'YOUR_GEMINI_KEY_HERE'
  });
  Logger.log('API keys saved successfully.');
}

// -------------------------------------------------------
// GETTER FUNCTIONS — Used by other files to retrieve keys
// -------------------------------------------------------
function getVirusTotalKey() {
  return PropertiesService.getScriptProperties().getProperty('VIRUSTOTAL_API_KEY');
}

function getAbuseIPDBKey() {
  return PropertiesService.getScriptProperties().getProperty('ABUSEIPDB_API_KEY');
}

function getIPQualityScoreKey() {
  return PropertiesService.getScriptProperties().getProperty('IPQUALITYSCORE_API_KEY');
}

function getSafeBrowsingKey() {
  return PropertiesService.getScriptProperties().getProperty('SAFEBROWSING_API_KEY');
}

function getGeminiApiKey() {
  return PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY');
}

