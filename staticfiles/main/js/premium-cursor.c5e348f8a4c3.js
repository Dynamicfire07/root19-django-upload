(function () {
  const body = document.body;
  const cursor = document.querySelector('[data-testid="custom-cursor"]');
  const halo = cursor?.querySelector('.premium-cursor__halo');

  if (!body || !cursor || !halo) return;

  const interactiveSelector = [
    'a', 'button', '.btn', '[role="button"]', '.nav-link', 
    '.card', '.feature-card', '.form-check-input', '.answer-btn', 
    '.side-button', 'select', '.form-select', '.interactive-item',
    '.module-rail-item', '.relevant-card', '.panel-mini-card'
  ].join(',');
  
  const textSelector = [
    'input:not([type="checkbox"]):not([type="radio"]):not([type="submit"]):not([type="button"])', 
    'textarea', '.form-control'
  ].join(',');

  let visible = false;
  let isMorphing = false;
  let currentTarget = null;
  let rafId = 0;
  let pointerX = window.innerWidth / 2;
  let pointerY = window.innerHeight / 2;
  let currentX = pointerX;
  let currentY = pointerY;
  let targetX = pointerX;
  let targetY = pointerY;
  let currentWidth = 42;
  let currentHeight = 42;
  let targetWidth = 42;
  let targetHeight = 42;
  let currentRadius = 999;
  let targetRadius = 999;
  let premiumCursorEnabled = false;

  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
  const lerp = (start, end, amount) => start + (end - start) * amount;

  function canUsePremiumCursor() {
    if (window.innerWidth <= 991) {
      return false;
    }

    if (!window.matchMedia) {
      return true;
    }

    return window.matchMedia('(any-hover: hover) and (any-pointer: fine)').matches;
  }

  function enablePremiumCursor() {
    if (premiumCursorEnabled) return;
    premiumCursorEnabled = true;
    body.dataset.premiumCursor = 'enabled';
    cursor.hidden = false;
  }

  function disablePremiumCursor() {
    premiumCursorEnabled = false;
    delete body.dataset.premiumCursor;
    currentTarget = null;
    isMorphing = false;
    cursor.hidden = true;
    cursor.classList.remove('is-interactive', 'is-morphing', 'is-pressed', 'is-text');
    hideCursor();
  }

  function parseRadius(rawValue) {
    const parsed = Number.parseFloat(rawValue);
    if (Number.isFinite(parsed)) {
      return clamp(parsed, 12, 999);
    }
    return 999;
  }

  function syncHalo() {
    cursor.style.setProperty('--cursor-halo-x', `${currentX}px`);
    cursor.style.setProperty('--cursor-halo-y', `${currentY}px`);
    halo.style.width = `${currentWidth}px`;
    halo.style.height = `${currentHeight}px`;
    halo.style.borderRadius = currentRadius >= 999 ? '999px' : `${currentRadius}px`;
  }

  function tick() {
    const positionEase = isMorphing ? 0.2 : 0.16;
    const sizeEase = isMorphing ? 0.24 : 0.18;

    currentX = lerp(currentX, targetX, positionEase);
    currentY = lerp(currentY, targetY, positionEase);
    currentWidth = lerp(currentWidth, targetWidth, sizeEase);
    currentHeight = lerp(currentHeight, targetHeight, sizeEase);
    currentRadius = lerp(currentRadius, targetRadius, sizeEase);

    syncHalo();
    rafId = window.requestAnimationFrame(tick);
  }

  function ensureLoop() {
    if (!rafId) {
      rafId = window.requestAnimationFrame(tick);
    }
  }

  function setCursorMode(target) {
    const textTarget = target && target.closest(textSelector);
    const interactiveTarget = target && target.closest(interactiveSelector);

    if (interactiveTarget && !textTarget) {
      currentTarget = interactiveTarget;
      isMorphing = true;
      cursor.classList.add('is-morphing');

      const rect = currentTarget.getBoundingClientRect();
      const style = window.getComputedStyle(currentTarget);
      targetWidth = rect.width + 12;
      targetHeight = rect.height + 12;
      targetRadius = parseRadius(style.borderRadius);
      targetX = rect.left + rect.width / 2;
      targetY = rect.top + rect.height / 2;
    } else {
      isMorphing = false;
      currentTarget = null;
      cursor.classList.remove('is-morphing');
      targetWidth = 42;
      targetHeight = 42;
      targetRadius = 999;
      targetX = pointerX;
      targetY = pointerY;
    }

    cursor.classList.toggle('is-interactive', Boolean(interactiveTarget && !textTarget));
    cursor.classList.toggle('is-text', Boolean(textTarget));
  }

  function showCursor() {
    if (!canUsePremiumCursor()) return;

    enablePremiumCursor();

    if (!visible) {
      visible = true;
      cursor.classList.add('is-visible');
    }
  }

  function hideCursor() {
    visible = false;
    cursor.classList.remove('is-visible');
  }

  window.addEventListener('mousemove', function (event) {
    if (!canUsePremiumCursor()) {
      disablePremiumCursor();
      return;
    }
    
    pointerX = event.clientX;
    pointerY = event.clientY;

    if (!isMorphing) {
      targetX = pointerX;
      targetY = pointerY;
    }
    
    showCursor();
    ensureLoop();
    setCursorMode(event.target);
  }, { passive: true });

  window.addEventListener('scroll', () => {
    if (!currentTarget) return;
    setCursorMode(currentTarget);
  }, { passive: true });

  window.addEventListener('resize', () => {
    if (!canUsePremiumCursor()) {
      disablePremiumCursor();
      return;
    }

    enablePremiumCursor();

    if (currentTarget) {
      setCursorMode(currentTarget);
    }
  });

  window.addEventListener('mousedown', () => cursor.classList.add('is-pressed'));
  window.addEventListener('mouseup', () => cursor.classList.remove('is-pressed'));
  document.addEventListener('mouseleave', hideCursor);
  
  // Initialization
  cursor.hidden = true;
  syncHalo();
})();
