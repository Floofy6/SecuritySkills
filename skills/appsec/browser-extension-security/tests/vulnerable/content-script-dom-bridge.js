window.addEventListener("message", (event) => {
  if (!event.data || event.data.type !== "renderExport") {
    return;
  }

  const panel = document.getElementById("extension-export-panel");
  panel.innerHTML = event.data.html;

  chrome.runtime.sendMessage({
    action: event.data.action,
    projectId: event.data.projectId,
    exportUrl: event.data.exportUrl
  });
});
