/* Snapshot polling and SSE connection management */
'use strict';

var KPolling = {
  timer: null,
  evtSource: null,

  start: function() {
    this.poll();
    this.timer = setInterval(this.poll.bind(this), KState.pollInterval);
    this.connectSSE();
  },

  stop: function() {
    if (this.timer) clearInterval(this.timer);
    if (this.evtSource) this.evtSource.close();
  },

  poll: function() {
    if (KState.paused) return;
    fetch('/api/snapshot')
      .then(function(r) { return r.json(); })
      .then(function(snap) {
        var prev = KState.prevSnap;
        KState.pushSnap(snap);
        KState.prevSnap = snap;

        KGauges.update(snap, prev);
        KCharts.update(snap, prev);
      })
      .catch(function() {
        KState.connected = false;
      });

    /* Guest name changes rarely; fetch in parallel, not chained */
    fetch('/stats')
      .then(function(r) { return r.json(); })
      .then(function(s) {
        if (s.guest) document.getElementById('guest').textContent = s.guest;
      })
      .catch(function() {});
  },

  connectSSE: function() {
    if (this.evtSource) this.evtSource.close();

    this.evtSource = new EventSource('/api/events');
    this.evtSource.addEventListener('syscall', function(e) {
      try {
        var d = JSON.parse(e.data);
        KEvents.addEvent('syscall', d);
      } catch(err) {}
    });
    this.evtSource.addEventListener('process', function(e) {
      try {
        var d = JSON.parse(e.data);
        KEvents.addEvent('process', d);
      } catch(err) {}
    });
    this.evtSource.onopen = function() { KState.connected = true; };
    this.evtSource.onerror = function() { KState.connected = false; };
  }
};
