'use strict';

var log = document.getElementById('status');

function restore_options () {
  chrome.storage.local.get({
    positives: 3,
    whitelist: 'audio, video, text/plain'
  }, (prefs) => {
    Object.keys(prefs).forEach (name => {
      document.getElementById(name)[typeof prefs[name] === 'boolean' ? 'checked' : 'value'] = prefs[name];
    });
  });
}

function save_options() {
  let prefs = {
    whitelist: document.getElementById('whitelist').value
      .split(',')
      .map(s => s.trim())
      .filter((s, i, l) => s && l.indexOf(s) === i)
      .join(', '),
    positives: Math.max(1, document.getElementById('positives').value)
  };

  chrome.storage.local.set(prefs, () => {
    log.textContent = 'Options saved.';
    setTimeout(() => log.textContent = '', 750);
    restore_options();
  });
}

document.addEventListener('DOMContentLoaded', restore_options);
document.getElementById('save').addEventListener('click', () => {
  try {
    save_options();
  }
  catch (e) {
    log.textContent = e.message;
    setTimeout(() => log.textContent = '', 750);
  }
});
