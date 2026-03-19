/* SSE event feed panel */
'use strict';

var KEvents = {
  feed: null,
  autoScroll: true,
  filters: { syscall: true, process: true, errorsOnly: false },

  init: function() {
    this.feed = document.getElementById('event-feed');
  },

  addEvent: function(type, data) {
    if (!this.feed) return;

    /* Apply filters */
    if (type === 'syscall' && !this.filters.syscall) return;
    if (type === 'process' && !this.filters.process) return;
    if (this.filters.errorsOnly && type === 'syscall' && data.err === 0 && data.disp !== 'enosys') return;

    KState.pushEvent(data);

    var el = document.createElement('div');
    el.className = 'ev';

    if (type === 'syscall') {
      var cls = 'sc-' + data.disp;
      if (data.err !== 0) cls = 'sc-error';
      el.className += ' ' + cls;

      var lat;
      if (data.lat_ns < 1000)
        lat = data.lat_ns + 'ns';
      else if (data.lat_ns < 1000000)
        lat = (data.lat_ns / 1000).toFixed(1) + 'us';
      else
        lat = (data.lat_ns / 1000000).toFixed(1) + 'ms';

      var span = function(cls, txt) {
        var s = document.createElement('span');
        if (cls) s.className = cls;
        s.textContent = txt;
        return s;
      };
      el.appendChild(span('ev-name', data.name || '?'));
      el.appendChild(span('ev-disp', data.disp));
      el.appendChild(document.createTextNode(
        ' pid=' + data.pid + ' ret=' + data.ret +
        (data.err ? ' err=' + data.err : '') + ' '));
      el.appendChild(span('ev-lat', lat));
      var detail = document.createElement('div');
      detail.className = 'ev-detail';
      detail.textContent = 'nr=' + data.nr +
        ' args=[' + (data.args ? data.args.join(',') : '') + ']' +
        ' ts=' + data.ts;
      el.appendChild(detail);
    } else if (type === 'process') {
      el.className += ' proc';
      var name = document.createElement('span');
      name.className = 'ev-name';
      name.textContent = '[' + data.action + ']';
      el.appendChild(name);
      el.appendChild(document.createTextNode(
        ' pid=' + data.pid +
        (data.cmd ? ' cmd=' + data.cmd : '') +
        (data.code !== undefined ? ' code=' + data.code : '')));
    }

    /* Click to expand */
    el.addEventListener('click', function() {
      el.classList.toggle('expanded');
    });

    /* Insert at top */
    this.feed.insertBefore(el, this.feed.firstChild);

    /* Trim old events */
    while (this.feed.children.length > 500)
      this.feed.removeChild(this.feed.lastChild);
  }
};
