'use strict';

var args = document.location.search.substr(1).split('&').map(s => s.split('=')).reduce((p, c) => {
  p[c[0]] = decodeURIComponent(c[1]);
  return p;
}, {});

function summary (obj) {
  let styles =
    'table {' +
    '  white-space: nowrap;' +
    '  font-family: "Helvetica Neue",Helvetica,Arial,sans-serif;' +
    '  border-collapse: collapse;' +
    '  border-spacing: 0px;' +
    '  font-size: 13px;' +
    '  line-height: 20px;' +
    '  color: #333;' +
    '  table-layout: fixed;' +
    '}' +
    'th {' +
    '  border-bottom: 1px solid #DDD;' +
    '  padding: 8px;' +
    '  text-align: left;' +
    '}' +
    'td {' +
    '  padding: 8px;' +
    '  overflow: hidden;' +
    '  text-overflow: ellipsis;' +
    '}' +
    'tr:nth-child(even) {' +
    '  background: #F9F9F9;' +
    '}' +
    '.clean {' +
    '  color: #33AF99;' +
    '}' +
    '.defected {' +
    '  color: #ED3237;' +
    '}';
  let html =
    '<html>' +
    '  <head>' +
    '    <link rel="shortcut icon" href="data:image/png;base64,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">' +
    '    <meta charset="utf-8">' +
    '    <meta name=viewport content="width=device-width, initial-scale=1">' +
    '    <title>Scan Plus Report</title>' +
    '    <style><!-- styles --></style>' +
    '  </head>' +
    '  <table width="100%">' +
    '    <colgroup>' +
    '      <col width=120>' +
    '      <col width=100>' +
    '      <col>' +
    '    </colgroup>' +
    '    <tr>' +
    '      <th>URL Scanner</th><th>Result</th><th style="width: 100%; text-align: left">Detail</th>' +
    '    </tr>' +
    '    <!-- body -->' +
    '  </table>' +
    '</html>';

  let body = '';
  for (let i in obj.scans) {
    body += '<tr><td>' + i + '</td><td class="' + (obj.scans[i].detected ? 'defected' : 'clean') + '">' + obj.scans[i].result + '</td><td>' + (obj.scans[i].detail || '-') + '</td></tr>';
  }

  return 'data:text/html,' + encodeURIComponent(html.replace('<!-- body -->', body).replace('<!-- styles -->', styles));
}


chrome.runtime.onMessage.addListener(request => {
  if (request.cmd === 'report') {
    if (request.download) {
      document.querySelector('[data-id=filename]').textContent = request.download.filename || 'Unknown';

    }
    else {
      document.querySelector('[data-id=filename]').textContent = request.result.download.filename || 'Unknown';

    }
    document.querySelector('[data-id=url]').textContent = request.result.download.url;
    document.querySelector('[data-id=time]').textContent = (new Date(request.result.download.startTime)).toLocaleString();
    document.querySelector('[data-id=report]').textContent = request.result.positives + '/' + request.result.total;
    document.querySelector('[data-id=permalink]').href = document.querySelector('[data-id=permalink]').textContent = request.result.permalink;

    document.querySelector('iframe').src = summary(request.result);
  }
});

if (args.url) {
  chrome.runtime.sendMessage({
    cmd: 'get-report',
    url: args.url
  });
}
