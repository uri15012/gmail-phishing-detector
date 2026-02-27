/**
 * UI.gs
 * Builds the Gmail Add-on interface using Google's CardService.
 */


// -------------------------------------------------------
// MAIN VERDICT CARD
// -------------------------------------------------------

function buildVerdictCard(analysis) {
  var verdict = analysis.verdict;
  var score   = analysis.score;
  var color   = getVerdictColor(verdict);
  var emoji   = getVerdictEmoji(verdict);

  var card = CardService.newCardBuilder();
  card.setName('verdict');

  var header = CardService.newCardHeader()
    .setTitle(emoji + '  ' + verdict)
    .setSubtitle('Threat Score: ' + score + ' / 100')
    .setImageStyle(CardService.ImageStyle.CIRCLE);
  card.setHeader(header);

  var scoreSection = CardService.newCardSection();

  var filledBlocks = Math.round(score / 10);
  var emptyBlocks  = 10 - filledBlocks;
  var scoreBar     = '█'.repeat(filledBlocks) + '░'.repeat(emptyBlocks);

  scoreSection.addWidget(
    CardService.newTextParagraph()
      .setText('<b><font color="' + color + '">' + scoreBar + '</font></b>')
  );

  scoreSection.addWidget(
    CardService.newTextParagraph()
      .setText(
        '<b>Sender:</b> ' + (analysis.senderName || analysis.senderEmail) + '  ' +
        '<b>Domain:</b> ' + (analysis.domain || 'Unknown') + '  ' +
        (analysis.originatingIp ? '<b>Origin IP:</b> ' + analysis.originatingIp : '')
      )
  );

  card.addSection(scoreSection);

  if (analysis.explanations && analysis.explanations.length > 0) {
    var signalSection = CardService.newCardSection()
      .setHeader('Signals Detected (' + analysis.explanations.length + ')');

    for (var i = 0; i < analysis.explanations.length; i++) {
      var exp = analysis.explanations[i];
      signalSection.addWidget(
        CardService.newTextParagraph()
          .setText(
            '<b>' + exp.signal + '</b> (+' + exp.weight + ' pts)  ' +
            '<font color="#666666">' + exp.details + '</font>'
          )
      );
      if (i < analysis.explanations.length - 1) {
        signalSection.addWidget(CardService.newDivider());
      }
    }
    card.addSection(signalSection);

  } else {
    var cleanSection = CardService.newCardSection();
    cleanSection.addWidget(
      CardService.newTextParagraph()
        .setText('No suspicious signals detected. This email appears to be legitimate.')
    );
    card.addSection(cleanSection);
  }

  var actionsSection = CardService.newCardSection()
    .setHeader('Actions');

  var blacklistAction = CardService.newAction()
    .setFunctionName('addSenderToBlacklist')
    .setParameters({ email: analysis.senderEmail });

  actionsSection.addWidget(
    CardService.newTextButton()
      .setText('Blacklist This Sender')
      .setOnClickAction(blacklistAction)
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor('#c0392b')
  );

  actionsSection.addWidget(
    CardService.newTextButton()
      .setText('Settings')
      .setOnClickAction(CardService.newAction().setFunctionName('openSettingsCard'))
  );

  card.addSection(actionsSection);

  return card.build();
}


// -------------------------------------------------------
// BLACKLIST QUICK-ADD HANDLER
// -------------------------------------------------------

function addSenderToBlacklist(e) {
  var email = e.parameters.email;
  var result = addToBlacklist(email);

  var notification = CardService.newNotification()
    .setText(result.success ? result.message : result.message);

  return CardService.newActionResponseBuilder()
    .setNotification(notification)
    .build();
}


// -------------------------------------------------------
// MANAGEMENT CONSOLE
// -------------------------------------------------------

function openSettingsCard(e) {
  var card = CardService.newCardBuilder();
  card.setName('settings');

  var header = CardService.newCardHeader()
    .setTitle('Management Console')
    .setSubtitle('Settings & Preferences');
  card.setHeader(header);

  var section = CardService.newCardSection()
    .setHeader('Options');

  section.addWidget(
    CardService.newTextButton()
      .setText('Manage Blacklist')
      .setOnClickAction(CardService.newAction().setFunctionName('buildBlacklistCard'))
  );

  section.addWidget(
    CardService.newTextButton()
      .setText('Toggle Signals On/Off')
      .setOnClickAction(CardService.newAction().setFunctionName('buildSignalSettingsCard'))
  );

  section.addWidget(
    CardService.newTextButton()
      .setText('View Scan History')
      .setOnClickAction(CardService.newAction().setFunctionName('buildHistoryCard'))
  );

  section.addWidget(
    CardService.newTextButton()
      .setText('Export Blacklist')
      .setOnClickAction(CardService.newAction().setFunctionName('buildExportBlacklistCard'))
  );

  card.addSection(section);
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card.build()))
    .build();
}


// -------------------------------------------------------
// BLACKLIST CARD HANDLERS
// -------------------------------------------------------

function handleAddToBlacklist(e) {
  var entry = e.formInput.new_entry;
  var result = addToBlacklist(entry);

  var notification = CardService.newNotification()
    .setText(result.success ? result.message : result.message);

  return CardService.newActionResponseBuilder()
    .setNotification(notification)
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}

function handleRemoveFromBlacklist(e) {
  var entry = e.parameters.entry;
  removeFromBlacklist(entry);

  var notification = CardService.newNotification()
    .setText(entry + ' removed from blacklist.');

  return CardService.newActionResponseBuilder()
    .setNotification(notification)
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}


// -------------------------------------------------------
// ERROR CARD
// -------------------------------------------------------

function buildErrorCard(errorMessage) {
  var card = CardService.newCardBuilder();

  var header = CardService.newCardHeader()
    .setTitle('Analysis Error')
    .setSubtitle('Something went wrong');
  card.setHeader(header);

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newTextParagraph()
      .setText(
        'The add-on encountered an error while analyzing this email.  ' +
        '<b>Error:</b> <font color="#c0392b">' + (errorMessage || 'Unknown error') + '</font>  ' +
        'Please try reopening the email. If the problem persists, check that all API keys are configured correctly by running <b>setApiKeys()</b> in the Apps Script editor.'
      )
  );
  card.addSection(section);

  return card.build();
}
