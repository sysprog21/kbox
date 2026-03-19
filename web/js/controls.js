/* UI controls: theme, pause/resume, filters */
'use strict';

var KControls = {
  init: function() {
    /* Theme toggle */
    var btn = document.getElementById('btn-theme');
    if (btn) btn.addEventListener('click', function() {
      document.body.classList.toggle('light');
      localStorage.setItem('kbox-theme',
        document.body.classList.contains('light') ? 'light' : 'dark');
    });

    /* Restore theme */
    if (localStorage.getItem('kbox-theme') === 'light')
      document.body.classList.add('light');

    /* Pause/resume */
    var pauseBtn = document.getElementById('btn-pause');
    if (pauseBtn) pauseBtn.addEventListener('click', function() {
      KState.paused = !KState.paused;
      pauseBtn.textContent = KState.paused ? 'Resume' : 'Pause';
      fetch('/api/control', {
        method: 'POST',
        body: JSON.stringify({ action: KState.paused ? 'pause' : 'resume' })
      }).catch(function(){});
    });

    /* Event filters */
    var fSc = document.getElementById('f-syscall');
    var fProc = document.getElementById('f-process');
    var fErr = document.getElementById('f-errors');
    if (fSc) fSc.addEventListener('change', function() {
      KEvents.filters.syscall = fSc.checked;
    });
    if (fProc) fProc.addEventListener('change', function() {
      KEvents.filters.process = fProc.checked;
    });
    if (fErr) fErr.addEventListener('change', function() {
      KEvents.filters.errorsOnly = fErr.checked;
    });
  }
};
