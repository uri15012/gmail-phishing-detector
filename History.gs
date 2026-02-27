/**
 * History.gs
 * Tracks and displays the scan history of analyzed emails.
 * Stores the last 20 scan results in PropertiesService (per-user storage).
 */

var HISTORY_KEY = 'SCAN_HISTORY';
var MAX_HISTORY = 20;

/**
 * Saves a scan result to the history log.
 * Called automatically after every email analysis in Code.gs.
 */
function saveScanToHistory(analysis) { // analysis received from code.gs and contains score, email details 
  try {
    var history = getScanHistory();

    var entry = {
      timestamp:   new Date().toISOString(),
      senderEmail: analysis.senderEmail || 'Unknown',
      senderName:  analysis.senderName  || '',
      subject:     (analysis.subject    || 'No subject').substring(0, 80),
      score:       analysis.score       || 0,
      verdict:     analysis.verdict     || 'Safe',
      domain:      analysis.domain      || ''
    };

    history.unshift(entry); // newest appears first

    if (history.length > MAX_HISTORY) {
      history = history.slice(0, MAX_HISTORY);
    }

    PropertiesService.getUserProperties().setProperty(HISTORY_KEY, JSON.stringify(history));
    // because the property service can only store
  } catch (e) {
    Logger.log('History save error: ' + e.message);
  }
}

/**
 * Returns the full scan history array.
 */
function getScanHistory() {
  var raw = PropertiesService.getUserProperties().getProperty(HISTORY_KEY);
  if (!raw) return [];
  try {
    return JSON.parse(raw);
  } catch (e) {
    return [];
  }
}

/**
 * Clears the entire scan history.
 */
function clearScanHistory() {
  PropertiesService.getUserProperties().deleteProperty(HISTORY_KEY);

  var notification = CardService.newNotification()
    .setText('Scan history cleared.');

  return CardService.newActionResponseBuilder()
    .setNotification(notification)
    .setStateChanged(true)// for the UI to know 
    .build();
}

/**
 * Builds the scan history card for the management console.
 * CardService it's google's framework we use to build the UI
 */
function buildHistoryCard() {
  var history = getScanHistory();
  var card = CardService.newCardBuilder(); // create the empty panel
  card.setName('history');

  var header = CardService.newCardHeader()
    .setTitle('Scan History')
    .setSubtitle('Last ' + Math.min(history.length, MAX_HISTORY) + ' analyzed emails');
  card.setHeader(header);

  if (history.length === 0) {
    var emptySection = CardService.newCardSection();
    emptySection.addWidget(
      CardService.newTextParagraph()
        .setText('No emails have been analyzed yet. Open an email to start scanning.')
    );
    card.addSection(emptySection);
  } else { 
    var section = CardService.newCardSection()
      .setHeader('Recent Scans');
    // if history exists loop through each scan and add it to the card
    for (var i = 0; i < history.length; i++) {
      var entry = history[i];

      var date = new Date(entry.timestamp);
      var dateStr = (date.getMonth() + 1) + '/' + date.getDate() + '/' + date.getFullYear() +
                    ' ' + date.getHours() + ':' + (date.getMinutes() < 10 ? '0' : '') + date.getMinutes();

      var verdictPrefix = '';
      if (entry.verdict === 'Malicious')  verdictPrefix = '[!] ';
      if (entry.verdict === 'Suspicious') verdictPrefix = '[?] ';
      if (entry.verdict === 'Safe')       verdictPrefix = '[OK] ';

      var row = CardService.newDecoratedText()
        .setTopLabel(dateStr + '  |  Score: ' + entry.score + '/100')
        .setText(verdictPrefix + entry.verdict + '  -  ' + (entry.senderEmail || entry.domain))
        .setBottomLabel(entry.subject);

      section.addWidget(row);
    }

    var clearAction = CardService.newAction().setFunctionName('clearScanHistory');
    section.addWidget(
      CardService.newTextButton()
        .setText('Clear History')
        .setOnClickAction(clearAction)
    );

    card.addSection(section);
  }

  var backSection = CardService.newCardSection();
  var backAction = CardService.newAction().setFunctionName('openSettingsCard');
  backSection.addWidget(
    CardService.newTextButton()
      .setText('Back to Settings')
      .setOnClickAction(backAction)
  );
  card.addSection(backSection);

  return card.build();
}
