/* Bootstrap: wire everything together */
'use strict';

document.addEventListener('DOMContentLoaded', function() {
  KEvents.init();
  KCharts.init();
  KControls.init();
  KPolling.start();
});
