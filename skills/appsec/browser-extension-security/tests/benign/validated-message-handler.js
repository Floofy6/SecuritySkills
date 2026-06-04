const ALLOWED_EXTENSION_ID = chrome.runtime.id;
const ALLOWED_ORIGINS = new Set(["https://app.example.com"]);

function originFromSender(sender) {
  if (sender.origin) {
    return sender.origin;
  }
  if (sender.url) {
    return new URL(sender.url).origin;
  }
  return "";
}

function isValidExportMessage(message) {
  return Boolean(
    message &&
      message.action === "exportCurrentProject" &&
      typeof message.projectId === "string" &&
      /^[a-z0-9-]{1,64}$/i.test(message.projectId)
  );
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const origin = originFromSender(sender);

  if (sender.id !== ALLOWED_EXTENSION_ID || !ALLOWED_ORIGINS.has(origin)) {
    sendResponse({ error: "unauthorized" });
    return false;
  }

  if (!isValidExportMessage(message)) {
    sendResponse({ error: "invalid_message" });
    return false;
  }

  chrome.storage.local.set({ lastExportedProject: message.projectId });
  sendResponse({ ok: true });
  return false;
});
