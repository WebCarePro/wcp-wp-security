import { createRoot, render } from '@wordpress/element';
import App from './App';

function initApp() {
  const container = document.getElementById('wcp-scanner-root');
  if (!container) {
    return;
  }

  try {
    if (typeof createRoot === 'function') {
      const root = createRoot(container);
      root.render(<App />);
    } else if (typeof render === 'function') {
      render(<App />, container);
    }
  } catch (err) {
    console.error('WCP Security Scanner Mount Error:', err);
    container.innerHTML = '<div style="padding: 20px; color: red;">Failed to load WCP Scanner dashboard. Check browser console for details.</div>';
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
