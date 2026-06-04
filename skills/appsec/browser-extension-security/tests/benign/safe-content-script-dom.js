const TRUSTED_ORIGIN = "https://app.example.com";

window.addEventListener("message", (event) => {
  if (event.origin !== TRUSTED_ORIGIN || event.source !== window) {
    return;
  }

  if (!event.data || event.data.type !== "renderProjectName") {
    return;
  }

  if (typeof event.data.name !== "string" || event.data.name.length > 120) {
    return;
  }

  const panel = document.getElementById("extension-project-panel");
  panel.textContent = event.data.name;
});
