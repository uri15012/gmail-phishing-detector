/**
 * Settings.gs
 * Manages user preferences — toggle individual signals on or off.
 * Settings are saved per user using PropertiesService.
 */

var SETTINGS_KEY = 'USER_SIGNAL_SETTINGS';

var DEFAULT_SETTINGS = {
  SIGNAL_BLACKLIST:          true,
  SIGNAL_DISPLAY_NAME_SPOOF: true,
  SIGNAL_REPLY_TO:           true,
  SIGNAL_GEMINI:             true,
  SIGNAL_LINKS:              true,
  SIGNAL_VIRUSTOTAL:         true,
  SIGNAL_ABUSEIPDB:          true,
  SIGNAL_IPQUALITYSCORE:     true,
  SIGNAL_SAFE_BROWSING:      true
};

function getSignalSettings() {
  var raw = PropertiesService.getUserProperties().getProperty(SETTINGS_KEY);
  if (!raw) return DEFAULT_SETTINGS;
  try {
    var saved = JSON.parse(raw);
    var merged = {};
    for (var key in DEFAULT_SETTINGS) {
      merged[key] = (saved[key] !== undefined) ? saved[key] : DEFAULT_SETTINGS[key];
    }
    return merged;
  } catch (e) {
    return DEFAULT_SETTINGS;
  }
}

function saveSignalSettings(settings) {
  PropertiesService.getUserProperties().setProperty(SETTINGS_KEY, JSON.stringify(settings));
}

function isSignalEnabled(signalKey) {
  var settings = getSignalSettings();
  return settings[signalKey] !== false;
}

function toggleSignal(e) {
  var signalKey = e.parameters.signalKey;
  var settings = getSignalSettings();
  settings[signalKey] = !settings[signalKey];
  saveSignalSettings(settings);

  var state = settings[signalKey] ? 'enabled' : 'disabled';
  var label = signalKey.replace('SIGNAL_', '').replace(/_/g, ' ');

  var notification = CardService.newNotification()
    .setText(label + ' signal ' + state + '.');

  return CardService.newActionResponseBuilder()
    .setNotification(notification)
    .setStateChanged(true)
    .build();
}

function buildSignalSettingsCard() {
  var settings = getSignalSettings();
  var card = CardService.newCardBuilder();
  card.setName('signal_settings');

  var header = CardService.newCardHeader()
    .setTitle('Signal Settings')
    .setSubtitle('Enable or disable individual analysis signals');
  card.setHeader(header);

  var section = CardService.newCardSection()
    .setHeader('Toggle Signals');

  var signals = [
    { key: 'SIGNAL_BLACKLIST',          label: 'Personal Blacklist',         weight: 20 },
    { key: 'SIGNAL_DISPLAY_NAME_SPOOF', label: 'Display Name Spoofing',      weight: 15 },
    { key: 'SIGNAL_VIRUSTOTAL',         label: 'VirusTotal Reputation',      weight: 15 },
    { key: 'SIGNAL_ABUSEIPDB',          label: 'AbuseIPDB IP Reputation',    weight: 12 },
    { key: 'SIGNAL_REPLY_TO',           label: 'Reply-To Mismatch',          weight: 10 },
    { key: 'SIGNAL_GEMINI',             label: 'Gemini AI Analysis',         weight: 10 },
    { key: 'SIGNAL_IPQUALITYSCORE',     label: 'IPQualityScore Email Check', weight: 8  },
    { key: 'SIGNAL_LINKS',              label: 'Suspicious Links',           weight: 7  },
    { key: 'SIGNAL_SAFE_BROWSING',      label: 'Google Safe Browsing',       weight: 3  }
  ];

  for (var i = 0; i < signals.length; i++) {
    var sig = signals[i];
    var enabled = settings[sig.key] !== false;
    var statusText = enabled ? '[ON]  Active' : '[OFF] Inactive';
    var buttonLabel = enabled ? 'Disable' : 'Enable';

    var toggleAction = CardService.newAction()
      .setFunctionName('toggleSignal')
      .setParameters({ signalKey: sig.key });

    var row = CardService.newDecoratedText()
      .setTopLabel(sig.label + '  (' + sig.weight + ' pts)')
      .setText(statusText)
      .setButton(
        CardService.newTextButton()
          .setText(buttonLabel)
          .setOnClickAction(toggleAction)
      );

    section.addWidget(row);
  }

  var backAction = CardService.newAction().setFunctionName('openSettingsCard');
  section.addWidget(
    CardService.newTextButton()
      .setText('Back to Settings')
      .setOnClickAction(backAction)
  );

  card.addSection(section);
  return card.build();
}
