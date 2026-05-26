const WS_URL = "ws://localhost:9384";
const POLL_INTERVAL_MS = 1000;

let socket = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_DELAY_MS = 10000;

function connectWebSocket() {
  try {
    socket = new WebSocket(WS_URL);
    socket.onopen = () => { reconnectAttempts = 0; };
    socket.onclose = () => {
      socket = null;
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), MAX_RECONNECT_DELAY_MS);
      reconnectAttempts++;
      setTimeout(connectWebSocket, delay);
    };
    socket.onerror = () => {};
  } catch (e) {
    setTimeout(connectWebSocket, 5000);
  }
}

function extractDomain(url) {
  try { return new URL(url).hostname; }
  catch { return "unknown"; }
}

function isMonitorableUrl(url) {
  if (!url) return false;
  return url.startsWith("http://") || url.startsWith("https://");
}

async function sendTabSnapshot() {
  if (!socket || socket.readyState !== WebSocket.OPEN) return;

  try {
    const allTabs = await chrome.tabs.query({});
    const activeTabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    const activeTab = activeTabs.length > 0 ? activeTabs[0] : null;

    const tabList = allTabs
      .filter(tab => isMonitorableUrl(tab.url))
      .map(tab => ({
        url: tab.url,
        domain: extractDomain(tab.url),
        title: tab.title || "",
        active: tab.active && tab.windowId === (activeTab ? activeTab.windowId : -1),
        incognito: tab.incognito,
        window_id: tab.windowId,
      }));

    socket.send(JSON.stringify({
      type: "tab_snapshot",
      active_tab: activeTab && isMonitorableUrl(activeTab.url) ? {
        url: activeTab.url,
        domain: extractDomain(activeTab.url),
        title: activeTab.title || "",
      } : null,
      all_tabs: tabList,
      tab_count: tabList.length,
      incognito_count: tabList.filter(t => t.incognito).length,
      timestamp: Date.now() / 1000,
    }));
  } catch (e) {}
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) sendTabSnapshot();
});
chrome.tabs.onActivated.addListener(() => sendTabSnapshot());
chrome.tabs.onCreated.addListener(() => sendTabSnapshot());
chrome.tabs.onRemoved.addListener(() => sendTabSnapshot());
chrome.windows.onFocusChanged.addListener(() => sendTabSnapshot());

connectWebSocket();
setInterval(sendTabSnapshot, POLL_INTERVAL_MS);
