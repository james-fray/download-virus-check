'use strict';

const toast = document.getElementById('toast');

const restore = () => chrome.storage.local.get({
  positives: 3,
  whitelist: 'image/, audio/, video/, text/',
  key: '',
  log: false
}, prefs => {
  document.getElementById('key').value = prefs.key;
  document.getElementById('whitelist').value = prefs.whitelist;
  document.getElementById('positives').value = prefs.positives;
  document.getElementById('log').checked = prefs.log;
});

document.addEventListener('DOMContentLoaded', restore);
document.getElementById('save').addEventListener('click', () => {
  const prefs = {
    whitelist: document.getElementById('whitelist').value
      .split(/\s*,\s*/)
      .filter((s, i, l) => s && l.indexOf(s) === i)
      .join(', '),
    positives: Math.max(1, document.getElementById('positives').value),
    key: document.getElementById('key').value,
    log: document.getElementById('log').checked
  };

  chrome.storage.local.set(prefs, () => {
    toast.textContent = 'Options saved.';
    setTimeout(() => toast.textContent = '', 750);
    restore();
  });
});

// reset
document.getElementById('reset').addEventListener('click', e => {
  if (e.detail === 1) {
    toast.textContent = 'Double-click to reset!';
    window.setTimeout(() => toast.textContent = '', 750);
  }
  else {
    localStorage.clear();
    chrome.storage.local.clear(() => {
      chrome.runtime.reload();
      window.close();
    });
  }
});
// support
document.getElementById('support').addEventListener('click', () => chrome.tabs.create({
  url: chrome.runtime.getManifest().homepage_url + '?rd=donate'
}));
