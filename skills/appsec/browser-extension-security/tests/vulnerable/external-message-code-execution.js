chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  if (message.action === "run") {
    chrome.scripting.executeScript({
      target: { tabId: message.tabId },
      func: (code) => eval(code),
      args: [message.code],
      world: "MAIN"
    });
    sendResponse({ ok: true });
  }
});
