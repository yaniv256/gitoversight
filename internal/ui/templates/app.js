// GitOversight UI actions: every mutation is a fetch POST to /v1/human/*
// carrying the template-injected CSRF token. Native form posts are not a
// supported path (the session middleware validates the X-CSRF-Token header).
//
// No native dialogs: window.confirm() freezes the page thread, cannot be
// clicked by an agent driving the page through actions.json, and wedges the
// tab for everyone (2026-07-24). Confirmation is an in-page two-step arm:
// the first tap turns the button into the confirmation question, the second
// tap executes; it disarms by itself after a few seconds.
(function () {
  var meta = document.querySelector('meta[name="csrf-token"]');
  var csrf = meta ? meta.getAttribute('content') : '';
  document.addEventListener('toggle', function (event) {
    var details = event.target;
    if (!details || details.tagName !== 'DETAILS' || !details.open ||
        !details.hasAttribute('data-diff-url') || details.getAttribute('data-diff-loaded') === '1') return;
    // Mark before fetch so close/reopen cannot issue a duplicate request.
    details.setAttribute('data-diff-loaded', '1');
    var target = details.querySelector('.lazy-diff');
    if (!target) return;
    target.textContent = 'Loading diff…';
    fetch(details.getAttribute('data-diff-url'), { credentials: 'same-origin' }).then(function (response) {
      if (!response.ok) throw new Error('HTTP ' + response.status);
      return response.text();
    }).then(function (html) {
      target.innerHTML = html;
    }).catch(function (error) {
      target.textContent = 'Could not load this diff (' + error.message + '). Reload the review before authorizing.';
      target.className = 'lazy-diff notice deny';
    });
  }, true);
  function banner(kind, text) {
    var el = document.getElementById('banner');
    if (!el) return;
    // An empty kind clears the banner outright, so a dismissed confirmation
    // leaves no stale question hanging above the buttons.
    el.className = kind ? 'banner ' + kind : 'banner';
    el.textContent = text;
  }
  document.addEventListener('click', function (event) {
    var button = event.target.closest('[data-action]');
    if (!button) return;
    event.preventDefault();
    var url = button.getAttribute('data-url');
    var body = button.getAttribute('data-body') || '{}';
    var bodyId = button.getAttribute('data-body-id');
    if (bodyId) {
      var block = document.getElementById(bodyId);
      if (block) {
        // A form control holds typed input in .value; textContent returns only
        // the markup it was rendered with, so reading textContent from a
        // <textarea> silently sends an EMPTY note however much the reviewer
        // wrote. Pre-rendered blocks still use textContent.
        var isField = block.value !== undefined && block.tagName !== undefined &&
          (block.tagName === 'TEXTAREA' || block.tagName === 'INPUT');
        var raw = isField ? block.value : block.textContent;
        // A field carries prose, not JSON. Wrap it in the field the endpoint
        // expects; a pre-rendered block is already a JSON document.
        body = isField ? JSON.stringify({ note: raw }) : raw;
      }
    }
    var confirmText = button.getAttribute('data-confirm');
    if (confirmText && button.getAttribute('data-armed') !== '1') {
      button.setAttribute('data-armed', '1');
      button.setAttribute('data-label', button.textContent);
      // The QUESTION goes in the banner, where it can be as long as it needs to
      // be; the BUTTON keeps a short, unmissable instruction. Putting the full
      // sentence in the label made the button a paragraph of wrapped text whose
      // "tap again" instruction was buried at the end, and a reader who took the
      // time to read it ran out the disarm timer and had to start over
      // (2026-07-26). Never make the label carry the reasoning.
      banner('warn', confirmText);
      button.textContent = 'Tap again to confirm';
      // No auto-disarm. A timer that silently un-arms punishes the careful
      // reader for reading; the explicit Cancel below is the way out.
      var cancel = document.getElementById('confirm-cancel');
      if (!cancel) {
        cancel = document.createElement('button');
        cancel.id = 'confirm-cancel';
        cancel.className = 'btn secondary';
        cancel.type = 'button';
        cancel.textContent = 'Cancel';
        cancel.addEventListener('click', function (stop) {
          stop.preventDefault();
          stop.stopPropagation();
          button.removeAttribute('data-armed');
          button.textContent = button.getAttribute('data-label');
          banner('', '');
          cancel.remove();
        });
        button.parentNode.appendChild(cancel);
      }
      return;
    }
    button.removeAttribute('data-armed');
    if (button.getAttribute('data-label')) button.textContent = button.getAttribute('data-label');
    var armedCancel = document.getElementById('confirm-cancel');
    if (armedCancel) armedCancel.remove();
    banner('', '');
    button.disabled = true;
    fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: body
    }).then(function (response) {
      if (response.ok) { window.location.reload(); return; }
      if (response.status === 401 || response.status === 403) {
        // This used to claim "publishing needs a fresh sign-in" and offer a
        // login link. That was a GUESS — the API answers 403 for several
        // unrelated reasons and does not say which — and the guess was wrong,
        // so its remedy could not work. Yaniv signed in repeatedly, returned,
        // tapped publish, and got the same banner: an infinite loop built out
        // of a confident, incorrect diagnosis (2026-07-27).
        //
        // The step-up that message described has since been removed entirely;
        // it was never a requirement. A confident wrong message is worse than
        // an honest vague one, because it sends the reader to do something
        // futile instead of asking. So this now says only what is certainly
        // true: the action did not happen, and nothing changed.
        //
        // Do NOT auto-redirect. A banner shown for a moment before navigating
        // away is a message nobody reads, and the reader is left believing the
        // action succeeded (2026-07-26).
        banner('error', 'That did not go through, and nothing was published or changed. Your session may have expired — reload the page. If it happens again, the reason is in the server log; do not keep retrying.');
        button.disabled = false;
        return;
      }
      if (response.status === 409) {
        banner('error', 'That changed under you — reloading the latest state.');
        setTimeout(function () { window.location.reload(); }, 1200);
        return;
      }
      response.text().then(function (text) {
        var detail = '';
        try { detail = (JSON.parse(text).detail || JSON.parse(text).error || ''); } catch (ignored) { }
        banner('error', 'That did not go through (' + response.status + (detail ? ': ' + detail : '') + '). It is safe to retry.');
      });
      button.disabled = false;
    }).catch(function () {
      banner('error', 'Network problem — nothing was changed. Retry when ready.');
      button.disabled = false;
    });
  });
})();
