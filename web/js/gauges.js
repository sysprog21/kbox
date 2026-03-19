/* SVG arc gauges for the overview bar */
'use strict';

var KGauges = {
  /* Draw a semi-circle arc gauge. pct = 0..1 */
  drawArc: function(id, pct) {
    var el = document.getElementById(id);
    if (!el) return;
    pct = Math.max(0, Math.min(1, pct));
    /* Semi-circle from 180 to 0 degrees, radius 30, center 40,38 */
    var r = 30, cx = 40, cy = 38;
    var startAngle = Math.PI;
    var endAngle = Math.PI - (pct * Math.PI);
    var x1 = cx + r * Math.cos(startAngle);
    var y1 = cy + r * Math.sin(startAngle);
    var x2 = cx + r * Math.cos(endAngle);
    var y2 = cy + r * Math.sin(endAngle);
    var large = pct > 0.5 ? 1 : 0;
    if (pct <= 0) {
      el.setAttribute('d', '');
      return;
    }
    el.setAttribute('d',
      'M ' + x1 + ' ' + y1 +
      ' A ' + r + ' ' + r + ' 0 ' + large + ' 0 ' + x2 + ' ' + y2);
  },

  update: function(snap, prev) {
    /* Syscall rate */
    var scRate = KState.rate(snap, prev, 'dispatch.total');
    document.getElementById('g-syscalls-val').textContent =
      scRate < 1000 ? Math.round(scRate) : (scRate/1000).toFixed(1) + 'k';
    this.drawArc('g-syscalls-arc', Math.min(scRate / 5000, 1));

    /* Context switch rate */
    var csRate = KState.rate(snap, prev, 'context_switches');
    document.getElementById('g-ctx-val').textContent =
      csRate < 1000 ? Math.round(csRate) : (csRate/1000).toFixed(1) + 'k';
    this.drawArc('g-ctx-arc', Math.min(csRate / 10000, 1));

    /* Memory usage percentage */
    var memPct = 0;
    if (snap.mem && snap.mem.total > 0)
      memPct = 1 - (snap.mem.free / snap.mem.total);
    document.getElementById('g-mem-val').textContent =
      Math.round(memPct * 100) + '%';
    this.drawArc('g-mem-arc', memPct);

    /* FD usage */
    var fdUsed = snap.fd ? snap.fd.used : 0;
    var fdMax = snap.fd ? snap.fd.max : 1;
    document.getElementById('g-fd-val').textContent = fdUsed;
    this.drawArc('g-fd-arc', fdUsed / fdMax);

    /* Meta */
    var upS = snap.uptime_ns ? (snap.uptime_ns / 1e9).toFixed(0) : 0;
    var m = Math.floor(upS / 60), s = Math.floor(upS % 60);
    document.getElementById('uptime').textContent =
      m + 'm ' + s + 's';
    document.getElementById('sc-total').textContent =
      snap.dispatch ? snap.dispatch.total : 0;
  }
};
