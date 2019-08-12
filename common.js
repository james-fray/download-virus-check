'use strict';

const config = {
  key: '',
  delay: 20000,
  log: false
};

const app = {
  emit(id, value) {
    (app.callbacks[id] || []).forEach(callback => callback(value));
  },
  on(id, callback) {
    app.callbacks[id] = app.callbacks[id] || [];
    app.callbacks[id].push(callback);
  }
};
app.callbacks = {};

const cache = {};

let activeIDs = [];
let count = 0;

const logging = (...args) => config.log && console.log(...args);

chrome.browserAction.onClicked.addListener(() => chrome.notifications.create({
  type: 'basic',
  iconUrl: './data/icons/48.png',
  title: chrome.runtime.getManifest().name,
  message: 'Number of active scans: ' + count + '\n\nClick to "abort" all active scans.'
}));
chrome.notifications.onClicked.addListener(notificationId => {
  chrome.notifications.clear(notificationId);

  activeIDs.forEach(id => window.clearTimeout(id));
  count = 0;
  activeIDs = [];
  app.emit('reset-requested');
  app.emit('update-badge');
});

chrome.browserAction.setBadgeBackgroundColor({
  color: '#4790f5'
});

const post = (() => {
  let next = 0;

  app.on('reset-requested', () => {
    next = Date.now() + config.delay;
  });

  function run(url, data, resolve) {
    logging('run', url, data);
    const req = new XMLHttpRequest();
    req.open('POST', url, true);
    req.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
    req.onload = () => resolve({
      response: req.response,
      status: req.status
    });
    req.onerror = e => resolve({
      error: e.message || e || 'code ' + req.status,
      status: req.status
    });
    req.send(Object.entries(data).map(([key, value]) => key + '=' + encodeURIComponent(value), '').join('&'));
  }

  return (url, data) => new Promise(resolve => {
    const now = Date.now();
    if (now > next) {
      run(url, data, resolve);
      next = now + config.delay;
    }
    else {
      logging('postponed', url, data);
      const id = window.setTimeout((url, data, resolve) => {
        run(url, data, resolve);
        const index = activeIDs.indexOf(id);
        if (index !== -1) {
          activeIDs.splice(index, 1);
        }
      }, next - now, url, data, resolve);
      activeIDs.push(id);
      next += config.delay;
    }
  });
})();

function scan(download) {
  logging('scan', download);
  return post('https://www.virustotal.com/vtapi/v2/url/scan', {
    url: download.url,
    apikey: config.key
  }).then(req => {
    logging('scan response', req);
    // report back
    if (req.status === 204) {
      throw Error('virustotal -> scan -> exceeded the request rate limit');
    }
    else if (req.status !== 200) {
      throw Error('virustotal -> scan -> XMLHttpRequest rejection, code ' + req.status);
    }
    else if (req.error) {
      throw Error('virustotal -> scan -> XMLHttpRequest rejection, ' + req.error);
    }
    else if (!req.response) {
      throw Error('virustotal -> scan -> server returned empty response');
    }
    const json = JSON.parse(req.response);
    if (json.response_code === 0) {
      throw Error('virustotal -> scan -> server rejection, The requested resource is not among the finished, queued or pending scans');
    }
    else if (json.response_code !== 1) {
      throw Error('virustotal -> scan -> server rejection, ' + req.response.verbose_msg);
    }
    return {
      download,
      permalink: json.permalink,
      scan_id: json.scan_id
    };
  });
}

function report(obj, index = 0) {
  return post('https://www.virustotal.com/vtapi/v2/url/report', {
    resource: obj.scan_id,
    apikey: config.key
  }).then(function(req) {
    if (req.status === 204) {
      throw Error('virustotal -> report -> exceeded the request rate limit');
    }
    else if (req.status !== 200) {
      throw Error('virustotal -> report -> XMLHttpRequest rejection, code ' + req.status);
    }
    else if (!req.response) {
      throw Error('virustotal -> report -> server returned empty response');
    }
    const json = JSON.parse(req.response);
    if (json.response_code !== 1) {
      if (index > 5) {
        throw Error('virustotal -> report -> server rejection, ' + json.verbose_msg);
      }
      // report is not ready yet
      else {
        return report(obj, index + 1);
      }
    }

    return {
      download: obj.download,
      scan_id: json.scan_id,
      scan_date: json.scan_date,
      positives: json.positives,
      total: json.total,
      scans: json.scans,
      permalink: json.permalink
    };
  });
}

//
app.on('update-badge', () => chrome.browserAction.setBadgeText({
  text: count ? count + '' : ''
}));

//
chrome.runtime.onMessage.addListener((request, sender) => {
  if (request.cmd === 'get-report') {
    chrome.downloads.search({
      id: cache[request.url].download.id
    }, downloads => {
      chrome.tabs.sendMessage(sender.tab.id, {
        cmd: 'report',
        result: cache[request.url],
        download: downloads[0]
      });
      delete cache[request.url];
    });
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
    config.log = prefs.log;
    if (prefs.key === '') {
      if (prefs.prompt === false) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: '/data/icons/48.png',
          title: chrome.runtime.getManifest().name,
          message: 'Please set your free API key on the options page'
        }, () => chrome.storage.local.set({
          prompt: true
        }, () => chrome.runtime.openOptionsPage()));
      }
      return logging('API key is not detected', 'aborting');
    }
    config.key = prefs.key;
    const ignored = prefs.whitelist.split(', ').reduce((p, c) => p || c && download.mime.startsWith(c), false);
    if (ignored) {
      logging('Check is ignored', download.mime);
    }
    else {
      logging('queue', download);
      count += 1;
      app.emit('update-badge');
      scan(download).then(report).then(obj => {
        const url = obj.download.url;

        chrome.storage.local.get({
          positives: 3
        }, prefs => {
          if (obj.positives >= prefs.positives) {
            cache[url] = obj;

            const screenWidth = screen.availWidth;
            const screenHeight = screen.availHeight;
            const width = 500;
            const height = 600;

            chrome.windows.create({
              url: './data/window/index.html?url=' + encodeURIComponent(url),
              focused: true,
              type: 'panel',
              width,
              height,
              left: Math.round((screenWidth - width) / 2),
              top: Math.round((screenHeight - height) / 2)
            });
          }
          else {
            logging('Link passed anti-virus check');
          }
          count -= 1;
          app.emit('update-badge');
        });
      }).catch(e => {
        logging('Unexpected error occurred', e);
        count -= 1;
        app.emit('update-badge');
      });
    }
  });
});

// FAQs & Feedback
{
  const {onInstalled, setUninstallURL, getManifest} = chrome.runtime;
  const {name, version} = getManifest();
  const page = getManifest().homepage_url;
  onInstalled.addListener(({reason, previousVersion}) => {
    chrome.storage.local.get({
      'faqs': true,
      'last-update': 0
    }, prefs => {
      if (reason === 'install' || (prefs.faqs && reason === 'update')) {
        const doUpdate = (Date.now() - prefs['last-update']) / 1000 / 60 / 60 / 24 > 45;
        if (doUpdate && previousVersion !== version) {
          chrome.tabs.create({
            url: page + '?version=' + version +
              (previousVersion ? '&p=' + previousVersion : '') +
              '&type=' + reason,
            active: reason === 'install'
          });
          chrome.storage.local.set({'last-update': Date.now()});
        }
      }
    });
  });
  setUninstallURL(page + '?rd=feedback&name=' + encodeURIComponent(name) + '&version=' + version);
}
