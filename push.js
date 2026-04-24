// ═══════════════════════════════════════════════════════════════════════
// GMAO Push Notifications — helper commun (web + mobile)
// À charger depuis index.html et gmao_mobile.html
// ═══════════════════════════════════════════════════════════════════════
(function(global){
  function urlBase64ToUint8Array(base64){
    var padding = '='.repeat((4 - base64.length % 4) % 4);
    var b64 = (base64 + padding).replace(/-/g, '+').replace(/_/g, '/');
    var raw = atob(b64);
    var out = new Uint8Array(raw.length);
    for (var i=0; i<raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  async function enablePushNotifications(silent){
    // silent = true : pas de toast si déjà abonné ou erreur
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      if (!silent) alert('Votre navigateur ne supporte pas les notifications push.');
      return false;
    }
    try {
      // 1. Récupérer le SW
      var reg = await navigator.serviceWorker.ready;
      // 2. Vérifier si déjà abonné
      var existing = await reg.pushManager.getSubscription();
      if (existing) {
        // Déjà abonné côté navigateur : envoyer à nouveau au backend pour s'assurer qu'il l'a aussi
        await postSubscription(existing);
        return true;
      }
      // 3. Demander la permission
      var perm = await Notification.requestPermission();
      if (perm !== 'granted') {
        if (!silent) alert('Permission refusée. Les notifications ne seront pas envoyées.');
        return false;
      }
      // 4. Récupérer la clé publique VAPID depuis le backend
      var keyResp = await fetch('/api/push/vapid_public_key');
      var keyData = await keyResp.json();
      if (!keyData.key) {
        if (!silent) alert('Push non configuré côté serveur.');
        return false;
      }
      // 5. S'abonner
      var sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(keyData.key)
      });
      // 6. Envoyer l'abonnement au backend
      await postSubscription(sub);
      if (!silent) alert('✓ Notifications activées');
      return true;
    } catch (ex) {
      console.error('[push] Erreur activation :', ex);
      if (!silent) alert('Erreur activation notifications : ' + ex.message);
      return false;
    }
  }

  function getAuthToken(){
    // Web : window.S.token (variable en mémoire)
    // Mobile : variable globale TOKEN ou localStorage 'gmao_tok'
    try {
      if (window.S && window.S.token) return window.S.token;
    } catch(e) {}
    try {
      if (typeof TOKEN !== 'undefined' && TOKEN) return TOKEN;
    } catch(e) {}
    try {
      return localStorage.getItem('gmao_tok') || localStorage.getItem('gmao_token') || '';
    } catch(e) { return ''; }
  }

  async function postSubscription(sub){
    var subJson = sub.toJSON();
    var token = getAuthToken();
    await fetch('/api/push/subscribe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({
        endpoint: subJson.endpoint,
        keys: subJson.keys,
        user_agent: navigator.userAgent
      })
    });
  }

  async function disablePushNotifications(){
    try {
      var reg = await navigator.serviceWorker.ready;
      var sub = await reg.pushManager.getSubscription();
      if (!sub) return true;
      var subJson = sub.toJSON();
      await sub.unsubscribe();
      var token = getAuthToken();
      await fetch('/api/push/unsubscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ endpoint: subJson.endpoint })
      });
      return true;
    } catch (ex) {
      console.error('[push] Erreur désabonnement :', ex);
      return false;
    }
  }

  global.enablePushNotifications = enablePushNotifications;
  global.disablePushNotifications = disablePushNotifications;
})(window);
