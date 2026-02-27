/**
 * BlacklistExport.gs
 * Provides blacklist export functionality.
 *
 * Since Gmail Add-ons cannot directly download files to the user's computer,
 * we display the blacklist contents in a card so the user can copy and save it.
 * This is the standard approach for data export in Gmail Add-ons.
 */

/**
 * Builds a card that displays the full blacklist as plain text for easy copying.
 */
function buildExportBlacklistCard() {
  var list = getBlacklist();
  var card = CardService.newCardBuilder();
  card.setName('export_blacklist');

  var header = CardService.newCardHeader()
    .setTitle('Export Blacklist')
    .setSubtitle(list.length + ' entries total');
  card.setHeader(header);

  if (list.length === 0) {
    var emptySection = CardService.newCardSection();
    emptySection.addWidget(
      CardService.newTextParagraph()
        .setText('Your blacklist is empty. Add senders or domains from the main verdict card.')
    );
    card.addSection(emptySection);
  } else {

    // --- CSV Format Section ---
    var csvSection = CardService.newCardSection()
      .setHeader('CSV Format  (copy and save as .csv)');

    var csvContent = 'entry,type  ';
    for (var i = 0; i < list.length; i++) {
      var entry = list[i];
      var type = entry.indexOf('@') !== -1 ? 'email' : 'domain';
      csvContent += entry + ',' + type + '  ';
    }

    csvSection.addWidget(
      CardService.newTextParagraph().setText(csvContent)
    );
    card.addSection(csvSection);

    // --- Plain List Section ---
    var plainSection = CardService.newCardSection()
      .setHeader('Plain List  (one entry per line)');

    var plainContent = list.join('  ');
    plainSection.addWidget(
      CardService.newTextParagraph().setText(plainContent)
    );

    // Summary stats
    var emails  = list.filter(function(e) { return e.indexOf('@') !== -1; });
    var domains = list.filter(function(e) { return e.indexOf('@') === -1; });

    plainSection.addWidget(
      CardService.newTextParagraph()
        .setText( '  <b>Summary</b>  ' +'Total entries: ' + list.length + '  ' +
          'Email addresses: ' + emails.length + '  ' +
          'Domains: ' + domains.length
        )
    );

    card.addSection(plainSection);
  }

  // Back button
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
