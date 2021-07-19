'use strict';

const DELAY = 20 * 1000;
const cache = {};

const logging = (...args) => logging.print && console.log(...args);
chrome.storage.local.get({
  log: false
}, prefs => logging.print = prefs.log);

const notify = (e, c = () => {}) => chrome.notifications.create({
  type: 'basic',
  iconUrl: '/data/icons/48.png',
  title: chrome.runtime.getManifest().name,
  message: e.message || e
}, c);

chrome.action.onClicked.addListener(() => {
  chrome.alarms.clearAll();
  chrome.action.setBadgeText({
    text: ''
  });
  chrome.storage.local.set({
    queue: [],
    scanning: false
  });
  notify('Aborting active jobs');
});

chrome.action.setBadgeBackgroundColor({
  color: '#4790f5'
});

// badge
const badge = () => chrome.storage.local.get({
  queue: [],
  scanning: false
}, prefs => {
  const count = prefs.queue.length + (prefs.scanning ? 1 : 0);
  chrome.action.setBadgeText({
    text: count ? count.toString() : ''
  });
});

// check
const check = () => chrome.storage.local.get({
  queue: [],
  scanning: false,
  key: ''
}, prefs => {
  badge();
  if (prefs.scanning) {
    chrome.alarms.getAll(as => {
      if (as.length === 0) {
        chrome.alarms.create('scanning', {
          when: Date.now()
        });
      }
    });
    return;
  }

  if (prefs.queue.length === 0) {
    return;
  }
  logging('check', prefs);
  // let's scan a new one
  const href = prefs.queue.shift();
  const body = new URLSearchParams();
  body.set('apikey', prefs.key);
  body.set('url', href);

  fetch('https://www.virustotal.com/vtapi/v2/url/scan', {
    method: 'POST',
    body
  }).then(r => {
    if (r.ok) {
      if (r.status === 204) {
        throw Error('exceeded the request rate limit');
      }

      r.json().then(json => {
        if (json.error) {
          throw Error(json.error);
        }
        if (json.response_code === 0) {
          throw Error('The requested resource is not among the finished, queued or pending scans');
        }
        else if (json.response_code !== 1) {
          throw Error('response code is not equal to one');
        }

        chrome.storage.local.set({
          scanning: json['scan_id']
        });
        chrome.alarms.create('scanning', {
          when: Date.now() + DELAY
        });
      });
    }
    else {
      throw Error('response is not ok');
    }
  }).catch(e => logging('check aborted', e)).finally(() => chrome.storage.local.set(prefs));
});

chrome.runtime.onStartup.addListener(check);
chrome.runtime.onInstalled.addListener(check);
chrome.storage.onChanged.addListener(ps => {
  if (ps.queue) {
    check();
  }
  else if (ps.scanning && ps.scanning.newValue === false) {
    badge();
    chrome.alarms.create('check', {
      when: Date.now() + DELAY
    });
  }
});

// scanning
chrome.alarms.onAlarm.addListener(o => {
  if (o.name === 'scanning') {
    logging('scanning start', o);
    chrome.storage.local.get({
      scanning: false,
      key: ''
    }, prefs => {
      const next = reason => {
        logging('scanning end', reason);
        chrome.storage.local.set({
          scanning: false
        });
      };

      const body = new URLSearchParams();
      body.set('apikey', prefs.key);
      body.set('resource', prefs.scanning);
      fetch('https://www.virustotal.com/vtapi/v2/url/report', {
        method: 'POST',
        body
      }).then(r => {
        if (r.status === 204) { // exceeded the request rate limit
          return chrome.alarms.create('scanning', {
            when: Date.now() + DELAY
          });
        }
        if (r.ok) {
          r.json().then(json => {
            if (json.response_code !== 1) {
              next('response_code is ' + json.response_code); //
            }
            else {
              chrome.storage.local.get({
                positives: 3
              }, prefs => {
                if (json.positives >= prefs.positives) {
                  cache[json.url] = json;

                  chrome.windows.getCurrent(win => {
                    const width = 500;
                    const height = 600;

                    chrome.windows.create({
                      url: '/data/window/index.html?url=' + encodeURIComponent(json.url),
                      focused: true,
                      type: 'panel',
                      width,
                      height,
                      left: Math.round((win.width - width) / 2),
                      top: Math.round((win.height - height) / 2)
                    });
                  });
                }
                else {
                  logging('Link passed anti-virus check');
                }
                next('done');
              });
            }
          });
        }
        else {
          next('response is not ok');
        }
      }).catch(e => next(e.message));
    });
  }
  else if (o.name === 'check') {
    check();
  }
});

function scan(download) {
  chrome.storage.local.get({
    queue: []
  }, prefs => {
    prefs.queue.push(download.url);

    chrome.storage.local.set({
      queue: prefs.queue.filter((s, i, l) => s && l.indexOf(s) === i)
    });
  });
}

//
chrome.runtime.onMessage.addListener((request, sender) => {
  if (request.cmd === 'get-report') {
    chrome.downloads.search({
      url: request.url
    }, downloads => {
      chrome.tabs.sendMessage(sender.tab.id, {
        cmd: 'report',
        result: cache[request.url],
        download: downloads.length ? downloads[0] : false,
        url: request.url
      });
      setTimeout(() => {
        delete cache[request.url];
      }, 60 * 1000);
    });
  }
  else if (request.cmd === 'bring-to-front') {
    // chrome.windows.update(sender.tab.windowId, {
    //   focused: true
    // });
  }
});

// adding newly added download to the key list
chrome.downloads.onCreated.addListener(download => {
  if (download.state !== 'in_progress') {
    return logging('download is not in progress', 'aborting');
  }

  chrome.storage.local.get({
    whitelist: 'image/, audio/, video/, text/',
    key: '',
    prompt: false,
    log: false
  }, prefs => {
    if (prefs.key === '') {
      if (prefs.prompt === false) {
        notify('Please set your free API key on the options page', chrome.storage.local.set({
          prompt: true
        }, () => chrome.runtime.openOptionsPage()));
      }
      return logging('API key is not detected', 'aborting');
    }
    const ignored = prefs.whitelist.split(', ').reduce((p, c) => p || c && download.mime.startsWith(c), false);
    if (ignored) {
      logging('Check is ignored', download.mime);
    }
    else {
      scan(download);
    }
  });
});

/* FAQs & Feedback */
{
  const {management, runtime: {onInstalled, setUninstallURL, getManifest}, storage, tabs} = chrome;
  if (navigator.webdriver !== true) {
    const page = getManifest().homepage_url;
    const {name, version} = getManifest();
    onInstalled.addListener(({reason, previousVersion}) => {
      management.getSelf(({installType}) => installType === 'normal' && storage.local.get({
        'faqs': true,
        'last-update': 0
      }, prefs => {
        if (reason === 'install' || (prefs.faqs && reason === 'update')) {
          const doUpdate = (Date.now() - prefs['last-update']) / 1000 / 60 / 60 / 24 > 45;
          if (doUpdate && previousVersion !== version) {
            tabs.query({active: true, currentWindow: true}, tbs => tabs.create({
              url: page + '?version=' + version + (previousVersion ? '&p=' + previousVersion : '') + '&type=' + reason,
              active: reason === 'install',
              ...(tbs && tbs.length && {index: tbs[0].index + 1})
            }));
            storage.local.set({'last-update': Date.now()});
          }
        }
      }));
    });
    setUninstallURL(page + '?rd=feedback&name=' + encodeURIComponent(name) + '&version=' + version);
  }
}
