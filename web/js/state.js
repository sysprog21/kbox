/* Shared application state */
'use strict';

var KState = {
  paused: false,
  connected: false,
  snapHistory: [],     /* circular buffer of snapshots, max 300 */
  prevSnap: null,      /* previous snapshot for delta computation */
  events: [],          /* circular buffer of SSE events, max 10000 */
  charts: {},          /* Chart.js instances */
  maxHistory: 300,     /* ~15 min at 3s poll interval */
  maxEvents: 10000,
  pollInterval: 3000,

  pushSnap: function(snap) {
    this.snapHistory.push(snap);
    if (this.snapHistory.length > this.maxHistory)
      this.snapHistory.shift();
  },

  pushEvent: function(evt) {
    this.events.push(evt);
    if (this.events.length > this.maxEvents)
      this.events.shift();
  },

  /* Resolve a dotted path like "dispatch.total" on an object */
  _resolve: function(obj, path) {
    return path.split('.').reduce(function(o, k) { return o && o[k]; }, obj);
  },

  /* Compute rate (delta / seconds) between two snapshots */
  rate: function(cur, prev, field) {
    if (!prev || !cur) return 0;
    var dt = (cur.timestamp_ns - prev.timestamp_ns) / 1e9;
    if (dt <= 0) return 0;
    var cv = this._resolve(cur, field);
    var pv = this._resolve(prev, field);
    if (cv === undefined || pv === undefined) return 0;
    var r = (cv - pv) / dt;
    return r > 0 ? r : 0; /* clamp: counter resets produce negative deltas */
  }
};
