fetch('/api/site-config').then(response => response.ok ? response.json() : null).then(config => {
  if (!config) return;
  const origin = config.publicSiteUrl;
  if (origin) {
    const canonical = document.querySelector('link[rel="canonical"]');
    if (canonical) canonical.href = `${origin}${location.pathname}`;
    const image = document.querySelector('meta[property="og:image"]');
    if (image) image.content = `${origin}/og-image.svg`;
  }
  if (config.googleVerification) {
    let meta = document.querySelector('meta[name="google-site-verification"]');
    if (!meta) { meta = document.createElement('meta'); meta.name = 'google-site-verification'; document.head.append(meta); }
    meta.content = config.googleVerification;
  }
}).catch(() => {});
