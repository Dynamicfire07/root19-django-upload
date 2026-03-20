(function () {
  const body = document.body;
  const cursor = document.querySelector('[data-testid="custom-cursor"]');
  const halo = cursor?.querySelector('.premium-cursor__halo');

  if (!body || !cursor || !halo) return;

  const interactiveSelector = [
    'a', 'button', '.btn', '[role="button"]', '.nav-link', 
    '.card', '.feature-card', '.form-check-input', '.answer-btn', 
    '.side-button', 'select', '.form-select', '.interactive-item'
  ].join(',');
  
  const textSelector = [
    'input:not([type="checkbox"]):not([type="radio"]):not([type="submit"]):not([type="button"])', 
    'textarea', '.form-control'
  ].join(',');

  let visible = false;
  let isMorphing = false;
  let currentTarget = null;

  function setCursorMode(target) {
    const textTarget = target && target.closest(textSelector);
    const interactiveTarget = target && target.closest(interactiveSelector);

    if (interactiveTarget && !textTarget) {
      if (currentTarget !== interactiveTarget) {
        currentTarget = interactiveTarget;
        isMorphing = true;
        cursor.classList.add('is-morphing');
        
        // Morph logic
        const rect = currentTarget.getBoundingClientRect();
        const style = window.getComputedStyle(currentTarget);
        
        // Add a bit of padding (5px on each side)
        halo.style.width = (rect.width + 12) + 'px';
        halo.style.height = (rect.height + 12) + 'px';
        halo.style.borderRadius = style.borderRadius;
        
        // Exact snapping
        cursor.style.setProperty('--cursor-halo-x', (rect.left + rect.width / 2) + 'px');
        cursor.style.setProperty('--cursor-halo-y', (rect.top + rect.height / 2) + 'px');
      }
    } else {
      isMorphing = false;
      currentTarget = null;
      cursor.classList.remove('is-morphing');
      
      // Reset to default circle
      halo.style.width = '';
      halo.style.height = '';
      halo.style.borderRadius = '';
    }

    cursor.classList.toggle('is-text', Boolean(textTarget));
  }

  function showCursor() {
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
    if (window.innerWidth <= 991) return;
    
    const x = event.clientX;
    const y = event.clientY;
    
    // Only follow mouse if NOT morphing
    if (!isMorphing) {
      cursor.style.setProperty('--cursor-halo-x', x + 'px');
      cursor.style.setProperty('--cursor-halo-y', y + 'px');
    }
    
    showCursor();
    setCursorMode(event.target);
  }, { passive: true });

  window.addEventListener('mousedown', () => cursor.classList.add('is-pressed'));
  window.addEventListener('mouseup', () => cursor.classList.remove('is-pressed'));
  document.addEventListener('mouseleave', hideCursor);
  
  // Initialization
  body.dataset.premiumCursor = 'enabled';
  cursor.hidden = false;
})();
