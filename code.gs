/**
 * Code.gs
 * The main logic file for the Gmail Malicious Email Scorer.
 * Contains the entry point, email parser, and scoring engine.
 *
 * Scoring Model: Fixed-weight system where all signal weights sum to 100.
 * Each signal contributes a proportional score based on confidence level.
 */

// -------------------------------------------------------
// SCORING WEIGHTS — All weights sum to 100
// -------------------------------------------------------
var WEIGHTS = {
  BLACKLIST: 20,           // Strongest signal — user explicitly flagged this sender
  DISPLAY_NAME_SPOOF: 15,  // High — impersonating a known brand is a strong phishing indicator
  REPLY_TO_MISMATCH: 10,   // Medium — replies going to a different domain is suspicious
  GEMINI_ANALYSIS: 10,     // Medium — LLM detects manipulation, social engineering, phishing tone
  SUSPICIOUS_LINKS: 7,     // Medium — IP-based URLs, shorteners, very long URLs
  VIRUSTOTAL: 15,          // High — aggregated reputation from 70+ security engines
  ABUSEIPDB: 12,           // Medium-High — community-reported IP abuse history
  IPQUALITYSCORE: 8,       // Medium — email fraud scoring and disposable email detection
  SAFE_BROWSING: 3         // Lower — Google's URL blacklist (binary yes/no signal)
};

// -------------------------------------------------------
// ENTRY POINT — Called by Gmail everytime you open an email 
// -------------------------------------------------------
function buildAddOn(e) { // e - gmail fills 
  try {
    var emailData = extractEmailData(e);
    var analysis = calculateScore(emailData); // used in history
    // Save to scan history
    saveScanToHistory(analysis); 
    return buildVerdictCard(analysis); 
  } catch (error) {
    // If anything fails, show a friendly error card instead of blank panel
    return buildErrorCard(error.message);
  }
}

// -------------------------------------------------------
// extract headers, IP, links and who send it 
// -------------------------------------------------------
function extractEmailData(e) {
  var accessToken = e.gmail.accessToken; // reading field for a built in function 
  var messageId = e.gmail.messageId;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  var mail = GmailApp.getMessageById(messageId);

  var from = mail.getFrom() || ''; //. built in
  var body = mail.getPlainBody() || '';

  // Parse sender email and display name from the From header
  // Handles both "Name <email@domain.com>" and plain "email@domain.com" formats
  var senderEmail = '';
  var senderName = '';
  var angleMatch = from.match(/<(.+?)>/); // just take anything inside <>
  if (angleMatch) {
    senderEmail = angleMatch[1].trim().toLowerCase();
    senderName = from.replace(/<.+>/, '').trim();// only take the first part
  } else {
    senderEmail = from.trim().toLowerCase();
    senderName = '';
  }

  // Remove surrounding quotes from display name if present
  senderName = senderName.replace(/^["']|["']$/g, '').trim();

  var rawContent = mail.getRawContent() || '';

  return {
    fromHeader: from,
    senderEmail: senderEmail,
    senderName: senderName,
    subject: mail.getSubject() || '',
    body: body,
    headers: rawContent,
    urls: extractUrls(body),
    originatingIp: getOriginatingIp(rawContent)
  };
}

// -------------------------------------------------------
// URL EXTRACTION — Finds all URLs in the email body
// -------------------------------------------------------
function extractUrls(text) {
  if (!text) return [];
  var matches = text.match(/https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi );
  if (!matches) return [];
  // Clean trailing punctuation that may have been captured
  return matches.map(function(url) {
    return url.replace(/[.,;:!?)]+$/, '');
  });
}

// -------------------------------------------------------
// receives the email data from function extractEmailData and runs 8 checks:
// -------------------------------------------------------
function calculateScore(emailData) {
  var score = 0;
  var explanations = []; // initialize empty array for explanation 

  // 1. Blacklist Check — highest priority, user-defined
  // is the sender in my personal blacklist?
  if (isBlacklisted(emailData.senderEmail)) {
    score += WEIGHTS.BLACKLIST;
    explanations.push({
      signal: 'Blacklisted Sender',
      details: 'Sender ' + emailData.senderEmail + ' is on your personal blacklist.',
      weight: WEIGHTS.BLACKLIST
    });
  }

  // 2. Header Analysis — is the sender name fake?
  //it checks if the sender's display name claim to be one of 14 companies 
  //but the actual email domain doesn't match and checks where does your reply go 
  // if it will return to who send you the email
  var headerChecks = analyzeHeaders(emailData);
  score += headerChecks.score;
  explanations = explanations.concat(headerChecks.explanations);

  // 3. Content Analysis — reads the link extracted from the email body 
  // calls the function analyzeContent() which runs 3 simple rules 
  var contentChecks = analyzeContent(emailData);
  score += contentChecks.score;
  explanations = explanations.concat(contentChecks.explanations);

  // analyzeWithgemini is defined in a file called gemini.gs
  //sends the email subject to gemini and asks does it look like a phishing?
  try {
    var geminiResult = analyzeWithGemini(emailData.subject, emailData.body);
    score += geminiResult.score;
    explanations = explanations.concat(geminiResult.explanations);
  } catch (err) {
    Logger.log('Gemini analysis error: ' + err.message); // googleAppsScript runs in
    //google server and Logger.log lets the dev look inside what is happening 
  }

  
  var domain = emailData.senderEmail.split('@')[1] || '';//cuts the @ and gives an array takes the second item
  try {//emailData.urls - the list of links found inside the email body
    var vtResult = checkVirusTotal(domain, emailData.urls); // call the Virustotal.gs and check if it known as malicious both for domain and emaildata
    score += vtResult.score;
    explanations = explanations.concat(vtResult.explanations);
  } catch (err) {
    Logger.log('VirusTotal API error: ' + err.message);
  }

//checking the IP address of the server that sent the email instead of the domain
  try { 
    var abuseResult = checkAbuseIPDB(emailData.originatingIp);
    score += abuseResult.score;
    explanations = explanations.concat(abuseResult.explanations);
  } catch (err) {
    Logger.log('AbuseIPDB API error: ' + err.message);
  }

// used for full email address
  try {
    var ipqsResult = checkIPQualityScore(emailData.senderEmail);
    score += ipqsResult.score;
    explanations = explanations.concat(ipqsResult.explanations);
  } catch (err) {
    Logger.log('IPQualityScore API error: ' + err.message);
  }

// google safe browsing - uses google own database of dangerous websites that crawls constantly 
  try {
    var sbResult = checkSafeBrowsing(emailData.urls);
    score += sbResult.score;
    explanations = explanations.concat(sbResult.explanations); // explanation is the array
  } catch (err) {
    Logger.log('Safe Browsing API error: ' + err.message);
  }

  // math.round - no decimal to be professional 
  var finalScore = Math.min(Math.round(score), 100); 

  return {
    score: finalScore,
    explanations: explanations,
    verdict: getVerdict(finalScore),
    senderEmail: emailData.senderEmail,
    senderName: emailData.senderName,
    subject: emailData.subject,
    domain: domain,
    originatingIp: emailData.originatingIp
  };
}

// -------------------------------------------------------
// HEADER ANALYSIS - used in the header checks 
// -------------------------------------------------------
function analyzeHeaders(emailData) {
  var score = 0;
  var explanations = [];
  var domain = emailData.senderEmail.split('@')[1] || '';
  domain = domain.toLowerCase();

  // --- Display Name Spoofing Check ---
  // Detects when the display name claims to be a known brand
  // but the sending domain does not match that brand's legitimate domains.
  var knownBrands = [
    { name: 'paypal',      domains: ['paypal.com'] },
    { name: 'amazon',      domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr'] },
    { name: 'google',      domains: ['google.com', 'gmail.com', 'googlemail.com'] },
    { name: 'microsoft',   domains: ['microsoft.com', 'outlook.com', 'hotmail.com', 'live.com'] },
    { name: 'apple',       domains: ['apple.com', 'icloud.com'] },
    { name: 'netflix',     domains: ['netflix.com'] },
    { name: 'dhl',         domains: ['dhl.com', 'dhl.de'] },
    { name: 'facebook',    domains: ['facebook.com', 'facebookmail.com', 'meta.com'] },
    { name: 'instagram',   domains: ['instagram.com'] },
    { name: 'linkedin',    domains: ['linkedin.com'] },
    { name: 'wells fargo', domains: ['wellsfargo.com'] },
    { name: 'chase',       domains: ['chase.com', 'jpmorgan.com'] },
    { name: 'dropbox',     domains: ['dropbox.com'] },
    { name: 'spotify',     domains: ['spotify.com'] }
  ];

  var senderNameLower = (emailData.senderName || '').toLowerCase();

  if (senderNameLower) {
    for (var i = 0; i < knownBrands.length; i++) {
      var brand = knownBrands[i];
      if (senderNameLower.includes(brand.name)) {
        // Check if the actual sending domain matches any legitimate domain for this brand
        var isLegitimate = brand.domains.some(function(d) {
          return domain === d || domain.endsWith('.' + d);
        });
        if (!isLegitimate) {
          score += WEIGHTS.DISPLAY_NAME_SPOOF;
          explanations.push({
            signal: 'Display Name Spoofing',
            details: 'Sender claims to be "' + emailData.senderName + '" but email comes from ' + domain + '.',
            weight: WEIGHTS.DISPLAY_NAME_SPOOF
          });
          break; // the break is only when it's fake and we won't count twice if we have 2 matches
        }
      }
    }
  }

  // --- Reply-To Mismatch Check ---
  // first line - tries to find a line that starts with reply-to and extracts the email address
  var replyToMatch = emailData.headers.match(/^Reply-To:\s*<?([^\s>,]+)>?/im);
  if (replyToMatch) { // 
    var replyToAddress = replyToMatch[1].toLowerCase();
    var replyToDomain = replyToAddress.split('@')[1];
    if (replyToDomain && replyToDomain !== domain) {
      score += WEIGHTS.REPLY_TO_MISMATCH;
      explanations.push({
        signal: 'Reply-To Mismatch',
        details: 'Sender domain is ' + domain + ' but replies go to ' + replyToDomain + '.',
        weight: WEIGHTS.REPLY_TO_MISMATCH
      });
    }
  }

  return { score: score, explanations: explanations };
}

// -------------------------------------------------------
// checks email inside the email body using simple rules
// no external api needed just check if:
// -------------------------------------------------------
function analyzeContent(emailData) {
  var score = 0;
  var explanations = [];

  // --- Suspicious Links Check ---
  // Flags URLs that use IP addresses, are excessively long, or use URL shorteners
  var urls = emailData.urls || [];
  var suspiciousUrlCount = 0;
  var suspiciousUrlExamples = [];

  for (var i = 0; i < urls.length; i++) {
    var url = urls[i].toLowerCase();
    var isSuspicious = false;

    // IP-based URLs (e.g., http://192.168.1.1/login ) — almost always malicious
    if (url.match(/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ )) {
      isSuspicious = true;
    }
    // Very long URLs (common in phishing to hide the real destination)
    else if (url.length > 100) {
      isSuspicious = true;
    }
    // Known URL shorteners (used to hide the real destination)
    // limitation of my code I wouldn't pick smth like bit.ly/abc
    else if (url.match(/https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly|rebrand\.ly )/)) {
      isSuspicious = true;
    }

    if (isSuspicious) {
      suspiciousUrlCount++;
      // just in case it's very long 
      suspiciousUrlExamples.push(url.length > 60 ? url.substring(0, 57) + '...' : url);
    }
  }

  if (suspiciousUrlCount > 0) {
    // Scale: 1 suspicious URL = half score, 2+ = full score
    var linkRatio = Math.min(suspiciousUrlCount / 2, 1); // just the method to calculate 0.5 or 1
    var linkScore = Math.round(WEIGHTS.SUSPICIOUS_LINKS * linkRatio); // go to var WEIGHTS
    score += linkScore;
    explanations.push({
      signal: 'Suspicious Links',
      details: 'Found ' + suspiciousUrlCount + ' suspicious URL(s): ' + suspiciousUrlExamples.join(', ') + '.',
      weight: linkScore
    });
  }

  return { score: score, explanations: explanations };
}

// -------------------------------------------------------
// UTILITY FUNCTIONS
// -------------------------------------------------------

/**
 * Extracts the originating (external) IP address from email headers.
 * Parses the Received header chain from bottom to top to find the first
 * public IP address, which represents the original sending server.
 */
function getOriginatingIp(rawHeaders) {
  if (!rawHeaders) return null;

  var lines = rawHeaders.split('\n');
  var receivedHeaders = [];

  for (var i = 0; i < lines.length; i++) {
    if (lines[i].match(/^Received:/i)) {
      var fullHeader = lines[i];
      // Collect continuation lines (lines starting with whitespace)
      while (i + 1 < lines.length && lines[i + 1].match(/^\s/)) {
        i++;
        fullHeader += ' ' + lines[i].trim();
      }
      receivedHeaders.push(fullHeader);
    }
  }

  // Check from the last Received header (closest to the original sender)
  for (var j = receivedHeaders.length - 1; j >= 0; j--) {
    // Match IPs in both square brackets [1.2.3.4] and parentheses (1.2.3.4)
    var ipMatches = receivedHeaders[j].match(/[\[(](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\])]/g);
    if (ipMatches) {
      for (var k = 0; k < ipMatches.length; k++) {
        var ip = ipMatches[k].replace(/[\[\]()]/g, ''); // g replaces all occurrances 
        // Skip private and loopback IPs — we want the public originating IP
        if (!ip.match(/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.)/)) {
          return ip;
        }
      }
    }
  }
  return null;
}

/**
 * Maps a numeric score to a human-readable verdict.
 * 0-30: Safe, 31-60: Suspicious, 61-100: Malicious
 */
function getVerdict(score) {
  if (score > 60) return 'Malicious';
  if (score > 30) return 'Suspicious';
  return 'Safe';
}

/**
 * Returns a color-coded emoji for the verdict — used in the UI cards.
 */
function getVerdictEmoji(verdict) {
  if (verdict === 'Malicious') return '\u{1F534}';  // Red circle
  if (verdict === 'Suspicious') return '\u{1F7E1}'; // Yellow circle
  return '\u{1F7E2}';                                // Green circle
}

/**
 * Returns a hex color for the verdict — used for card styling.
 */
function getVerdictColor(verdict) {
  if (verdict === 'Malicious') return '#c0392b';
  if (verdict === 'Suspicious') return '#f39c12';
  return '#27ae60';
}

/**
 * Dummy authorization callback — required by appsscript.json manifest.
 */
function authCallback(e) {}
