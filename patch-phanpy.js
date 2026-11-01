const fs = require('fs');
let s = fs.readFileSync('src/app.jsx', 'utf8');
const target = `    const instanceURL = store.local.get('instanceURL');
    const code = decodeURIComponent(
      (window.location.search.match(/code=([^&]+)/) || [, ''])[1],
    );`;
const replacement = `    let instanceURL = store.local.get('instanceURL') || window.location.host;
    const urlParams = new URLSearchParams(window.location.search);
    const code = decodeURIComponent(
      (window.location.search.match(/code=([^&]+)/) || [, ''])[1],
    );
    const ssoToken = urlParams.get('token') || (window.location.hash.match(/[?&]token=([^&]+)/) || [])[1];
    if (ssoToken) {
      const ssoInstance = urlParams.get('instance') || (window.location.hash.match(/[?&]instance=([^&]+)/) || [])[1] || instanceURL;
      store.local.set('instanceURL', ssoInstance);
      window.history.replaceState({}, document.title, window.location.pathname || '/');
      (async () => {
        setUIState('loading');
        try {
          const client = initClient({ instance: ssoInstance, accessToken: ssoToken });
          await Promise.allSettled([
            initPreferences(client),
            initInstance(client, ssoInstance),
            initAccount(client, ssoInstance, ssoToken, undefined),
          ]);
          initStates();
          window.__IGNORE_GET_ACCOUNT_ERROR__ = true;
          setIsLoggedIn(true);
          setUIState('default');
          window.location.hash = '/';
        } catch (e) {
          console.error('SSO bootstrap error:', e);
          setUIState('error');
        }
      })();
      return;
    }`;
if (!s.includes(target)) {
  console.error('Target not found in src/app.jsx');
  process.exit(1);
}
s = s.replace(target, replacement);
fs.writeFileSync('src/app.jsx', s, 'utf8');
console.log('Successfully patched src/app.jsx for SSO token bootstrap');
