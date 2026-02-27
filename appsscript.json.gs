{
  "timeZone": "America/New_York",
  "dependencies": {},
  "exceptionLogging": "STACKDRIVER",
  "runtimeVersion": "V8",
  "oauthScopes": [
    "https://www.googleapis.com/auth/gmail.addons.execute",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/script.external_request",
    "https://www.googleapis.com/auth/script.storage"
  ],
  "urlFetchWhitelist": [
    "https://www.virustotal.com/",
    "https://api.abuseipdb.com/",
    "https://ipqualityscore.com/",
    "https://safebrowsing.googleapis.com/",
    "https://generativelanguage.googleapis.com/"
  ],
  "gmail": {
    "name": "Gmail Malicious Email Scorer",
    "logoUrl": "https://www.gstatic.com/images/icons/material/system/2x/security_black_48dp.png",
    "contextualTriggers": [
      {
        "unconditional": {},
        "onTriggerFunction": "buildAddOn"
      }
    ],
    "openLinkUrlPrefixes": [
      "https://"
    ],
    "universalActions": [
      {
        "text": "Manage Blacklist",
        "runFunction": "openSettingsCard"
      }
    ]
  }
}
