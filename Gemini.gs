/**
 * Gemini.gs
 * LLM-based phishing and social engineering analysis using Google Gemini API.
 *
 * Why Gemini instead of a keyword list?
 * A keyword list only catches emails that use known phrases.
 * Gemini understands the *intent* and *tone* of the email — it can detect
 * manipulation, urgency, and deception even when the attacker avoids common keywords.
 *
 * Model: gemini-2.5-flash (uses internal "thinking tokens" so we need higher maxOutputTokens)
 * Weight in scoring model: 10 points
 */

var GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent';// store in a variable in case we need to change the model

/**
 * Analyzes the email content using Gemini to detect phishing and social engineering.
 *
 * @param {string} subject - The email subject line
 * @param {string} body    - The plain text body of the email
 * @returns {{ score: number, explanations: Array }} - Score contribution and explanation
 */
function analyzeWithGemini(subject, body ) {
  var apiKey = getGeminiApiKey();

  // If no API key is configured, skip this check gracefully
  if (!apiKey) {
    Logger.log('Gemini API key not configured. Skipping LLM analysis.');
    return { score: 0, explanations: [] };
  }

  // Truncate body to avoid exceeding Apps Script 30-second execution timeout
  var truncatedBody = (body || '').substring(0, 3000);
  var truncatedSubject = (subject || '').substring(0, 200);

// Prompt Engineering: instruct Gemini to return a structured JSON response
// without searching through free text.
  var prompt = 'You are a cybersecurity expert specializing in phishing and email fraud detection.\n\n' +
    'Analyze the following email for signs of phishing, social engineering, scams, or malicious intent.\n\n' +
    'Look for:\n' +
    '- Urgency or fear tactics ("your account will be closed", "act now")\n' +
    '- Impersonation of trusted entities\n' +
    '- Requests for credentials, personal data, or payments\n' +
    '- Unrealistic promises (prizes, inheritances, lottery wins)\n' +
    '- Threats (legal action, arrest, account suspension)\n' +
    '- Manipulation or psychological pressure\n\n' +
    'EMAIL SUBJECT: ' + truncatedSubject + '\n\n' +
    'EMAIL BODY:\n' + truncatedBody + '\n\n' +
    'Respond ONLY with a valid JSON object in this exact format (no markdown, no explanation outside the JSON):\n' +
    '{"suspicion_score": <integer 0-10>, "reasoning": "<one sentence explanation>", "tactics_found": ["<tactic1>", "<tactic2>"]}\n\n' +
    'Where suspicion_score is:\n' +
    '0-2 = Clearly legitimate\n' +
    '3-5 = Mildly suspicious\n' +
    '6-8 = Likely phishing\n' +
    '9-10 = Almost certainly malicious';

  try {
    var response = UrlFetchApp.fetch(GEMINI_API_URL + '?key=' + apiKey, { // request to gemini
      method: 'post', // post - HTTP method for sending data
      contentType: 'application/json',
      muteHttpExceptions: true, // if there is an error we deal by ourself no crashing
      payload: JSON.stringify({ // convert js to json 
        contents: [{ // This is Gemini's required format for receiving a message
          parts: [{ text: prompt }]
        }],
        generationConfig: { // key to generate response
          temperature: 0,   //LLM generates probability for next word, we pick the word with the highest probability 
          maxOutputTokens: 1024   // maximum length 
        }
      })
    });

    var responseCode = response.getResponseCode();
    if (responseCode !== 200) { // HTTP response means 200 (everything worked)
      Logger.log('Gemini API returned HTTP ' + responseCode + ': ' + response.getContentText());// Writes the error to the Apps Script logs so you (the developer) can see 
      return { score: 0, explanations: [] }; // just put 0 without crashing
    }

    var responseJson = JSON.parse(response.getContentText());

    // Check if the response was cut off due to token limits
    var finishReason = responseJson.candidates[0].finishReason;
    if (finishReason === 'MAX_TOKENS') {
      Logger.log('Gemini response was truncated. Attempting to parse partial response.');
    }

    // Extract the text content from Gemini's response structure
    var rawText = responseJson.candidates[0].content.parts[0].text.trim();

    // // Remove markdown formatting (```json ... ```) that Gemini sometimes adds around the JSON
    rawText = rawText.replace(/^```json\s*/i, '').replace(/\s*```$/, '').trim();

    // This code tries its best to salvage something useful from a broken Gemini response. First try full parse → if that fails, try to at least get the score → if that also fails → return 0 and move on.
    var parsed;
    try {
      parsed = JSON.parse(rawText); 
    } catch (parseErr) { // f JSON.parse failed don't crash, come here instead.
      var scoreMatch = rawText.match(/"suspicion_score"\s*:\s*(\d+)/); // 
      if (scoreMatch) {
        parsed = {
          suspicion_score: parseInt(scoreMatch[1]),
          reasoning: 'Analysis completed (partial response from Gemini).',
          tactics_found: []
        };
        // Try to extract reasoning if available
        var reasonMatch = rawText.match(/"reasoning"\s*:\s*"([^"]+)/);
        if (reasonMatch) {
          parsed.reasoning = reasonMatch[1];
        }
      } else {
        Logger.log('Could not parse Gemini response: ' + rawText);
        return { score: 0, explanations: [] };
      }
    }

    var suspicionScore = parseInt(parsed.suspicion_score) || 0; // Take the score from Gemini's response (0-10) and convert it to a number. If it's missing or invalid → use 0 as default.
    var reasoning = parsed.reasoning || 'No reasoning provided.';
    var tactics = parsed.tactics_found || [];

    // Map Gemini's 0-10 scale to our weight (max 10 points in the scoring model)
    var contributedScore = Math.round((suspicionScore / 10) * WEIGHTS.GEMINI_ANALYSIS);

    if (contributedScore === 0) {
      return { score: 0, explanations: [] }; // no explaantion
    }

    var details = reasoning;
    if (tactics.length > 0) {
      details += ' Tactics detected: ' + tactics.join(', ') + '.';
    }

    return {
      score: contributedScore,
      explanations: [{
        signal: 'AI Content Analysis (Gemini)',
        details: details,
        weight: contributedScore
      }]
    };

  } catch (err) {
    Logger.log('Gemini analysis error: ' + err.message);
    return { score: 0, explanations: [] };
  }
}
