(function () {
  const body = document.body;
  const cursor = document.querySelector('[data-testid="custom-cursor"]');

  if (!body || !cursor) {
    return;
  }

  const interactiveSelector = [
    'a',
    'button',
    '.btn',
    '[role="button"]',
    '.nav-link',
    '.dropdown-item',
    '.card',
    '.feature-card',
    '.panel-mini-card',
    '.journey-card',
    '.module-card',
    '.hero-metric',
    '.brand-strip',
    '.brand-strip-items span',
    '.stat-card',
    '.qb-card',
    '.progress-card',
    '.checklist-card',
    '.spotlight-tab',
    '[data-cursor="interactive"]'
  ].join(',');

  const textSelector = [
    'input:not([type="checkbox"]):not([type="radio"]):not([type="range"]):not([type="submit"]):not([type="button"])',
    'textarea',
    'select',
    '[contenteditable="true"]',
    'pre',
    'code',
    '.form-control',
    '.form-select',
    '.cursor-native'
  ].join(',');

  const finePointerQuery = window.matchMedia('(hover: hover) and (pointer: fine)');
  const desktopQuery = window.matchMedia('(min-width: 992px)');
  const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');

  let enabled = false;
  let visible = false;
  let rafId = 0;

  let pointerX = -100;
  let pointerY = -100;
  let dotX = -100;
  let dotY = -100;
  let ringX = -100;
  let ringY = -100;

  function shouldEnable() {
    return finePointerQuery.matches && desktopQuery.matches && !reducedMotionQuery.matches;
  }

  function setCursorMode(target) {
    const textTarget = target && target.closest(textSelector);
    const interactiveTarget = !textTarget && target && target.closest(interactiveSelector);

    cursor.classList.toggle('is-text', Boolean(textTarget));
    cursor.classList.toggle('is-interactive', Boolean(interactiveTarget));
    body.classList.toggle('premium-cursor-text', Boolean(textTarget));
  }

  function stopLoop() {
    if (rafId) {
      cancelAnimationFrame(rafId);
      rafId = 0;
    }
  }

  function render() {
    rafId = 0;

    dotX += (pointerX - dotX) * 0.34;
    dotY += (pointerY - dotY) * 0.34;
    ringX += (pointerX - ringX) * 0.18;
    ringY += (pointerY - ringY) * 0.18;

    cursor.style.setProperty('--cursor-dot-x', dotX.toFixed(2) + 'px');
    cursor.style.setProperty('--cursor-dot-y', dotY.toFixed(2) + 'px');
    cursor.style.setProperty('--cursor-ring-x', ringX.toFixed(2) + 'px');
    cursor.style.setProperty('--cursor-ring-y', ringY.toFixed(2) + 'px');

    const dotDelta = Math.abs(pointerX - dotX) + Math.abs(pointerY - dotY);
    const ringDelta = Math.abs(pointerX - ringX) + Math.abs(pointerY - ringY);

    if (enabled && (visible || dotDelta > 0.08 || ringDelta > 0.08)) {
      rafId = requestAnimationFrame(render);
    }
  }

  function requestRender() {
    if (!rafId && enabled) {
      rafId = requestAnimationFrame(render);
    }
  }

  function showCursor() {
    if (!visible) {
      visible = true;
      cursor.classList.add('is-visible');
    }
  }

  function hideCursor() {
    visible = false;
    cursor.classList.remove('is-visible', 'is-pressed');
    body.classList.remove('premium-cursor-text');
  }

  function applyEnabledState(nextEnabled) {
    if (enabled === nextEnabled) {
      return;
    }

    enabled = nextEnabled;
    body.dataset.premiumCursor = enabled ? 'enabled' : 'disabled';
    cursor.hidden = !enabled;

    if (!enabled) {
      hideCursor();
      cursor.classList.remove('is-interactive', 'is-text');
      stopLoop();
      return;
    }

    requestRender();
  }

  function evaluate() {
    applyEnabledState(shouldEnable());
  }

  window.addEventListener(
    'mousemove',
    function (event) {
      if (!enabled) {
        return;
      }

      pointerX = event.clientX;
      pointerY = event.clientY;
      showCursor();
      setCursorMode(event.target);
      requestRender();
    },
    { passive: true }
  );

  window.addEventListener(
    'mouseover',
    function (event) {
      if (!enabled) {
        return;
      }

      setCursorMode(event.target);
    },
    { passive: true }
  );

  window.addEventListener(
    'mousedown',
    function () {
      if (!enabled) {
        return;
      }

      cursor.classList.add('is-pressed');
      requestRender();
    },
    { passive: true }
  );

  window.addEventListener(
    'mouseup',
    function () {
      cursor.classList.remove('is-pressed');
    },
    { passive: true }
  );

  document.addEventListener('mouseleave', hideCursor, { passive: true });
  window.addEventListener('blur', hideCursor);

  [finePointerQuery, desktopQuery, reducedMotionQuery].forEach(function (query) {
    if (typeof query.addEventListener === 'function') {
      query.addEventListener('change', evaluate);
    } else if (typeof query.addListener === 'function') {
      query.addListener(evaluate);
    }
  });

  evaluate();
})();
