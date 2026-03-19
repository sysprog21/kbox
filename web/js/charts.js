/* Chart.js instances for dashboard panels */
'use strict';

var KCharts = {
  /* Trim a chart's label/data arrays to maxHistory length */
  trimChart: function(ch) {
    if (ch.data.labels.length > KState.maxHistory) {
      ch.data.labels.shift();
      ch.data.datasets.forEach(function(d) { d.data.shift(); });
    }
  },

  colors: {
    file_io: '#58a6ff', dir: '#3fb950', fd_ops: '#d29922',
    identity: '#a371f7', memory: '#f85149', signals: '#db61a2',
    scheduler: '#79c0ff', other: '#8b949e'
  },

  init: function() {
    if (typeof Chart === 'undefined') return;
    Chart.defaults.color = '#8b949e';
    Chart.defaults.borderColor = '#30363d';
    Chart.defaults.font.size = 11;

    this.initSyscall();
    this.initMemory();
    this.initScheduler();
    this.initSoftirq();
  },

  initSyscall: function() {
    var ctx = document.getElementById('c-syscall');
    if (!ctx) return;
    var families = ['file_io','dir','fd_ops','identity','memory','signals','scheduler','other'];
    var datasets = families.map(function(f) {
      return {
        label: f, data: [],
        borderColor: KCharts.colors[f],
        backgroundColor: KCharts.colors[f] + '40',
        fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5
      };
    });
    KState.charts.syscall = new Chart(ctx, {
      type: 'line',
      data: { labels: [], datasets: datasets },
      options: {
        responsive: true, animation: false,
        scales: {
          x: { display: true, title: { display: false } },
          y: { stacked: true, beginAtZero: true, title: { display: true, text: 'calls/s' } }
        },
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } },
        interaction: { mode: 'index', intersect: false }
      }
    });
  },

  initMemory: function() {
    var ctx = document.getElementById('c-memory');
    if (!ctx) return;
    var names = ['used','buffers','cached','slab','free'];
    var cols = ['#f85149','#d29922','#58a6ff','#a371f7','#3fb950'];
    var datasets = names.map(function(n, i) {
      return {
        label: n, data: [],
        backgroundColor: cols[i] + '80',
        borderColor: cols[i], fill: true,
        pointRadius: 0, borderWidth: 1
      };
    });
    KState.charts.memory = new Chart(ctx, {
      type: 'line',
      data: { labels: [], datasets: datasets },
      options: {
        responsive: true, animation: false,
        scales: {
          x: { display: true },
          y: { stacked: true, beginAtZero: true, title: { display: true, text: 'kB' } }
        },
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } }
      }
    });
  },

  initScheduler: function() {
    var ctx = document.getElementById('c-scheduler');
    if (!ctx) return;
    KState.charts.scheduler = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          { label: 'ctx switch/s', data: [], borderColor: '#58a6ff', pointRadius: 0, borderWidth: 1.5, tension: 0.3 },
          { label: 'load 1m', data: [], borderColor: '#d29922', pointRadius: 0, borderWidth: 1.5, tension: 0.3, yAxisID: 'y1' }
        ]
      },
      options: {
        responsive: true, animation: false,
        scales: {
          x: { display: true },
          y: { beginAtZero: true, title: { display: true, text: 'switches/s' } },
          y1: { position: 'right', beginAtZero: true, title: { display: true, text: 'load' }, grid: { drawOnChartArea: false } }
        },
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } }
      }
    });
  },

  initSoftirq: function() {
    var ctx = document.getElementById('c-softirq');
    if (!ctx) return;
    var labels = ['HI','TIMER','NET_TX','NET_RX','BLOCK','IRQ_POLL','TASKLET','SCHED','HRTIMER','RCU'];
    var colors = ['#f85149','#d29922','#3fb950','#58a6ff','#a371f7','#db61a2','#79c0ff','#8b949e','#e3b341','#56d364'];
    KState.charts.softirq = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'count', data: new Array(10).fill(0),
          backgroundColor: colors
        }]
      },
      options: {
        responsive: true, animation: false,
        scales: { y: { beginAtZero: true } },
        plugins: { legend: { display: false } }
      }
    });
  },

  /* Update all charts with new snapshot data */
  update: function(snap, prev) {
    if (!prev) return;
    var label = new Date().toLocaleTimeString();

    /* Syscall family rates */
    if (KState.charts.syscall && snap.family && prev.family) {
      var ch = KState.charts.syscall;
      var fams = ['file_io','dir','fd_ops','identity','memory','signals','scheduler','other'];
      var dt = (snap.timestamp_ns - prev.timestamp_ns) / 1e9;
      if (dt > 0) {
        ch.data.labels.push(label);
        fams.forEach(function(f, i) {
          var rate = ((snap.family[f] || 0) - (prev.family[f] || 0)) / dt;
          ch.data.datasets[i].data.push(Math.max(0, rate));
        });
        KCharts.trimChart(ch);
        ch.update();
      }
    }

    /* Memory breakdown */
    if (KState.charts.memory && snap.mem) {
      var ch = KState.charts.memory;
      ch.data.labels.push(label);
      var m = snap.mem;
      var used = m.total - m.free - m.buffers - m.cached - m.slab;
      if (used < 0) used = 0;
      [used, m.buffers, m.cached, m.slab, m.free].forEach(function(v, i) {
        ch.data.datasets[i].data.push(v);
      });
      KCharts.trimChart(ch);
      ch.update();
    }

    /* Scheduler: ctx switch rate + loadavg */
    if (KState.charts.scheduler) {
      var ch = KState.charts.scheduler;
      ch.data.labels.push(label);
      var csRate = KState.rate(snap, prev, 'context_switches');
      ch.data.datasets[0].data.push(csRate);
      var la = (snap.loadavg && snap.loadavg[0] !== undefined) ? snap.loadavg[0] : 0;
      ch.data.datasets[1].data.push(la);
      KCharts.trimChart(ch);
      ch.update();
    }

    /* Softirq bar chart */
    if (KState.charts.softirq && snap.softirqs) {
      KState.charts.softirq.data.datasets[0].data = snap.softirqs.slice(0, 10);
      KState.charts.softirq.update();
    }

    /* Latency stats */
    if (snap.dispatch && snap.latency) {
      var total = snap.dispatch.total || 1;
      var avg_us = (snap.latency.total_ns / total / 1000).toFixed(1);
      var max_us = (snap.latency.max_ns / 1000).toFixed(1);
      document.getElementById('lat-avg').textContent = avg_us + 'us';
      document.getElementById('lat-max').textContent = max_us + 'us';
    }
  }
};
