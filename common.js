'use strict';

if (!Promise.defer) {
  Promise.defer = function () {
    var deferred = {};
    var promise = new Promise(function (resolve, reject) {
      deferred.resolve = resolve;
      deferred.reject  = reject;
    });
    deferred.promise = promise;
    return deferred;
  };
}

var apikey = '26c2e6f73ca56321b60df2f02b92bec014196d1b91ad8345db3db82a0c1630bc';

var app = {
  callbacks: {}
};

var cache = {};

app.emit = (id, value) => {
  (app.callbacks[id] || []).forEach(callback => callback(value));
};
app.on = (id, callback) => {
  app.callbacks[id] = app.callbacks[id] || [];
  app.callbacks[id].push(callback);
};

var activeIDs = [];
var count = 0;

function logging () {
  if (false) {
    console.error.apply(console.error, arguments);
  }
}

chrome.browserAction.onClicked.addListener(() => {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: './data/icons/48.png',
    title: 'Download Virus Checker',
    message: 'Number of active scans: ' + count + '\n\nClick to "abort" all active scans.',
  });
});
chrome.notifications.onClicked.addListener((notificationId) => {
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

var post = (function () {
  let next = 0;

  app.on('reset-requested', () => {
    next = (new Date()).getTime() + 20000;
  });

  function run (url, data, resolve) {
    let req = new XMLHttpRequest();
    req.open('POST', url, true);
    req.setRequestHeader('Content-Type','application/x-www-form-urlencoded; charset=UTF-8');
    req.onload = () => resolve({
      response: req.response,
      status: req.status
    });
    req.onerror = (e) => resolve({
      error: e.message || e || 'code ' + req.status,
      status: req.status
    });
    req.send(Object.entries(data).map(c => c[0] + '=' + encodeURIComponent(c[1]), '').join('&'));
  }

  return (url, data) => {
    let d = Promise.defer();
    let now = (new Date()).getTime();
    if (now > next) {
      run(url, data, d.resolve);
      next = now + 20000;
    }
    else {
      let id = window.setTimeout((url, data, resolve) => {
        run(url, data, resolve);
        let index = activeIDs.indexOf(id);
        if (index !== -1) {
          activeIDs.splice(index, 1);
        }
      }, next - now, url, data, d.resolve);
      activeIDs.push(id);
      next += 20000;
    }
    return d.promise;
  };
})();

function scan (download) {
  return post('https://www.virustotal.com/vtapi/v2/url/scan', {
    url: download.url,
    apikey
  })
  .then(req => {
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
    let json = JSON.parse(req.response);
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

function report (obj, index = 0) {
  return post('https://www.virustotal.com/vtapi/v2/url/report', {
    resource: obj.scan_id,
    apikey
  })
  .then(function (req) {
    if (req.status === 204) {
      throw Error('virustotal -> report -> exceeded the request rate limit');
    }
    else if (req.status !== 200) {
      throw Error('virustotal -> report -> XMLHttpRequest rejection, code ' + req.status);
    }
    else if (!req.response) {
      throw Error('virustotal -> report -> server returned empty response');
    }
    let json = JSON.parse(req.response);
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

function perform (download) {
  chrome.storage.local.get({
    whitelist: 'audio, video, text/plain'
  }, prefs => {
    let ignore = prefs.whitelist.split(', ').reduce((p, c) => p || download.mime.startsWith(c), false);
    if (!ignore) {
      count += 1;
      app.emit('update-badge');
      scan(download).then(report).then(obj => {
        let url = obj.download.url;

        chrome.storage.local.get({
          positives: 3
        }, prefs => {
          if (obj.positives >= prefs.positives) {
            cache[url] = obj;

            let screenWidth = screen.availWidth;
            let screenHeight = screen.availHeight;
            let width = 500;
            let height = 600;

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
    else {
      logging('Check is ignore', download.mime);
    }
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
chrome.downloads.onCreated.addListener(perform);

// FAQs
chrome.storage.local.get('version', (obj) => {
  let version = chrome.runtime.getManifest().version;
  if (obj.version !== version) {
    window.setTimeout(() => {
      chrome.storage.local.set({version}, () => {
        chrome.tabs.create({
          url: 'http://add0n.com/virus-checker.html?version=' + version + '&type=' + (obj.version ? ('upgrade&p=' + obj.version) : 'install')
        });
      });
    }, 3000);
  }
});
