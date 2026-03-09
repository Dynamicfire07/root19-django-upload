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
  const coarsePointerQuery = window.matchMedia('(pointer: coarse)');
  const desktopQuery = window.matchMedia('(min-width: 992px)');
  const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');

  let enabled = false;
  let visible = false;
  let rafId = 0;

  let pointerX = -100;
  let pointerY = -100;
  let cursorX = -100;
  let cursorY = -100;
  let haloX = -100;
  let haloY = -100;

  function shouldEnable() {
    const supportsDesktopPointer = finePointerQuery.matches || !coarsePointerQuery.matches;
    const hasTouchPoints = (navigator.maxTouchPoints || 0) > 0;
    return desktopQuery.matches && supportsDesktopPointer && !hasTouchPoints && !reducedMotionQuery.matches;
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
    const haloTargetX = pointerX + 10;
    const haloTargetY = pointerY + 12;

    cursorX += (pointerX - cursorX) * 0.42;
    cursorY += (pointerY - cursorY) * 0.42;
    haloX += (haloTargetX - haloX) * 0.16;
    haloY += (haloTargetY - haloY) * 0.16;

    cursor.style.setProperty('--cursor-pointer-x', cursorX.toFixed(2) + 'px');
    cursor.style.setProperty('--cursor-pointer-y', cursorY.toFixed(2) + 'px');
    cursor.style.setProperty('--cursor-halo-x', haloX.toFixed(2) + 'px');
    cursor.style.setProperty('--cursor-halo-y', haloY.toFixed(2) + 'px');

    const cursorDelta = Math.abs(pointerX - cursorX) + Math.abs(pointerY - cursorY);
    const haloDelta = Math.abs(pointerX - haloX) + Math.abs(pointerY - haloY);

    if (enabled && (visible || cursorDelta > 0.08 || haloDelta > 0.08)) {
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

  [finePointerQuery, coarsePointerQuery, desktopQuery, reducedMotionQuery].forEach(function (query) {
    if (typeof query.addEventListener === 'function') {
      query.addEventListener('change', evaluate);
    } else if (typeof query.addListener === 'function') {
      query.addListener(evaluate);
    }
  });

  evaluate();
})();
