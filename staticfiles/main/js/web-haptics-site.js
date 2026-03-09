/* Root19 global haptics layer powered by web-haptics (https://haptics.lochie.me) */
(function () {
  if (window.__R19_HAPTICS_BOOTSTRAPPED__) return;
  window.__R19_HAPTICS_BOOTSTRAPPED__ = true;

  const LOCAL_LIB_URL =
    typeof window !== "undefined" && window.R19_HAPTICS_LIB_URL
      ? String(window.R19_HAPTICS_LIB_URL)
      : null;
  const CDN_LIB_URL = "https://cdn.jsdelivr.net/npm/web-haptics@0.0.6/dist/index.mjs";
  const LIB_URLS = [LOCAL_LIB_URL, CDN_LIB_URL].filter(Boolean);
  const STORAGE_KEY = "r19_haptics_enabled";
  const DEBUG_KEY = "r19_haptics_debug";
  const DEFAULT_PATTERNS = {
    success: [{ duration: 30 }, { delay: 60, duration: 40 }],
    warning: [{ duration: 40 }, { delay: 100, duration: 40 }],
    error: [{ duration: 40 }, { delay: 40, duration: 40 }, { delay: 40, duration: 40 }],
    light: [{ duration: 15 }],
    medium: [{ duration: 25 }],
    heavy: [{ duration: 35 }],
    soft: [{ duration: 40 }],
    rigid: [{ duration: 10 }],
    selection: [{ duration: 8 }],
    nudge: [{ duration: 80 }, { delay: 80, duration: 50 }],
    buzz: [{ duration: 1000 }]
  };
  const INTERACTIVE_SELECTOR = [
    "a[href]",
    "button",
    "[role='button']",
    ".btn",
    ".nav-link",
    ".dropdown-item",
    "summary",
    "[data-bs-toggle]",
    "input[type='button']",
    "input[type='submit']",
    "input[type='reset']"
  ].join(", ");
  const STRONG_SELECTOR = [
    "button[type='submit']",
    "input[type='submit']",
    ".btn-primary",
    ".btn-success",
    ".btn-danger",
    "[data-bs-toggle='modal']",
    "[data-bs-toggle='collapse']",
    "[data-bs-toggle='dropdown']"
  ].join(", ");
  const CONTROL_SELECTOR = "input[type='checkbox'], input[type='radio'], select, input[type='range']";

  let haptics = null;
  let defaultPatterns = {};
  let enabled = true;
  let lastTriggerAt = 0;
  let handlersBound = false;
  let hapticsSource = "none";

  const readEnabledState = () => {
    try {
      return localStorage.getItem(STORAGE_KEY) !== "off";
    } catch (error) {
      return true;
    }
  };

  const writeEnabledState = (value) => {
    try {
      localStorage.setItem(STORAGE_KEY, value ? "on" : "off");
    } catch (error) {
      // Ignore storage failures (private mode/blocked storage).
    }
  };

  const readDebugState = () => {
    const search = String(window.location && window.location.search || "");
    if (search.includes("hapticsDebug=1")) return true;
    try {
      return localStorage.getItem(DEBUG_KEY) === "on";
    } catch (error) {
      return false;
    }
  };

  const now = () => Date.now();
  const hasUserActivation = () => {
    if (typeof navigator === "undefined" || !navigator.userActivation) return true;
    return navigator.userActivation.isActive || navigator.userActivation.hasBeenActive;
  };

  const isDisabledElement = (el) => {
    if (!el) return true;
    if (el.closest("[data-haptic='off']")) return true;
    return Boolean(el.matches("[disabled], [aria-disabled='true']"));
  };

  const resolvePattern = (pattern) => {
    if (pattern == null) return "selection";
    if (typeof pattern === "number") return pattern;
    if (Array.isArray(pattern)) return pattern;
    if (typeof pattern === "object") return pattern;

    const name = String(pattern).trim().toLowerCase();
    if (!name) return "selection";
    if (defaultPatterns[name]) return defaultPatterns[name];
    return name;
  };

  const convertPatternToVibrateArray = (pattern) => {
    if (typeof pattern === "number") {
      return [Math.max(1, Math.floor(pattern))];
    }

    if (Array.isArray(pattern)) {
      if (!pattern.length) return [];
      if (typeof pattern[0] === "number") {
        return pattern.map((n) => Math.max(0, Math.floor(Number(n) || 0)));
      }

      const seq = [];
      pattern.forEach((step, index) => {
        if (!step) return;
        const delay = Math.max(0, Math.floor(Number(step.delay || 0)));
        const duration = Math.max(1, Math.floor(Number(step.duration || 0)));
        if (delay > 0) {
          if (seq.length && index > 0) {
            seq.push(delay);
          } else {
            seq.push(0, delay);
          }
        }
        seq.push(duration);
      });
      return seq;
    }

    if (pattern && typeof pattern === "object" && Array.isArray(pattern.pattern)) {
      return convertPatternToVibrateArray(pattern.pattern);
    }

    if (typeof pattern === "string") {
      const preset = DEFAULT_PATTERNS[pattern.toLowerCase()];
      if (preset) return convertPatternToVibrateArray(preset);
    }

    return convertPatternToVibrateArray("selection");
  };

  const createFallbackHaptics = () => {
    const supportsVibrate = typeof navigator !== "undefined" && typeof navigator.vibrate === "function";
    const canUseVibrate = () => {
      if (!supportsVibrate) return false;
      if (!navigator.userActivation) return true;
      return navigator.userActivation.isActive || navigator.userActivation.hasBeenActive;
    };
    return {
      trigger(pattern) {
        if (!canUseVibrate()) return Promise.resolve();
        const sequence = convertPatternToVibrateArray(pattern);
        if (!sequence.length) return Promise.resolve();
        try {
          navigator.vibrate(sequence);
        } catch (error) {
          return Promise.resolve();
        }
        return Promise.resolve();
      },
      cancel() {
        if (!canUseVibrate()) return;
        try {
          navigator.vibrate(0);
        } catch (error) {
          // Ignore unsupported/blocked cancellation attempts.
        }
      },
      destroy() {}
    };
  };

  const trigger = (pattern, minGapMs = 50, options) => {
    if (!enabled || !haptics) return;
    if (!hasUserActivation()) return;
    const elapsed = now() - lastTriggerAt;
    if (elapsed < minGapMs) return;

    lastTriggerAt = now();
    haptics.trigger(resolvePattern(pattern), options).catch(() => {
      // Swallow runtime errors (navigation/unload races, unsupported devices).
    });
  };

  const getClickPattern = (target) => {
    const customNode = target.closest("[data-haptic]");
    if (customNode) {
      const custom = customNode.getAttribute("data-haptic");
      if (custom && custom !== "off") return custom;
      if (custom === "off") return null;
    }

    if (target.closest(STRONG_SELECTOR)) return "medium";
    if (target.closest("[data-bs-toggle='tab'], [data-bs-toggle='pill']")) return "selection";
    return "light";
  };

  const bindGlobalHandlers = () => {
    if (handlersBound) return;
    handlersBound = true;

    document.addEventListener(
      "click",
      (event) => {
        const target = event.target.closest(INTERACTIVE_SELECTOR);
        if (!target || isDisabledElement(target)) return;

        const isSubmitButton = target.matches("button[type='submit'], input[type='submit']");
        if (isSubmitButton) return; // Submit event has its own medium feedback.

        const pattern = getClickPattern(target);
        if (pattern) trigger(pattern, 45);
      },
      true
    );

    document.addEventListener(
      "submit",
      (event) => {
        if (event.defaultPrevented) return;
        const form = event.target;
        if (!(form instanceof HTMLFormElement)) return;
        if (form.closest("[data-haptic='off']")) return;
        trigger("medium", 70);
      },
      true
    );

    document.addEventListener(
      "invalid",
      () => {
        trigger("error", 140);
      },
      true
    );

    document.addEventListener(
      "change",
      (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) return;
        if (!target.matches(CONTROL_SELECTOR)) return;
        if (isDisabledElement(target)) return;
        trigger("selection", 35);
      },
      true
    );

    // Surface backend outcome states with semantic haptics.
    const hasErrorState =
      document.querySelector(".alert-danger, .alert-error, .errorlist, .is-invalid, .messages .error") !== null;
    const hasSuccessState =
      document.querySelector(".alert-success, .messages .success, .messages .safe-success") !== null;

    if (hasErrorState) {
      trigger("error", 0);
    } else if (hasSuccessState) {
      trigger("success", 0);
    }
  };

  const exposeControls = (WebHapticsClass) => {
    window.R19Haptics = {
      trigger(pattern = "selection", options) {
        trigger(pattern, 0, options);
      },
      enable() {
        enabled = true;
        writeEnabledState(true);
      },
      disable() {
        enabled = false;
        writeEnabledState(false);
      },
      isEnabled() {
        return enabled;
      },
      isSupported() {
        return Boolean(WebHapticsClass && WebHapticsClass.isSupported);
      },
      source() {
        return hapticsSource;
      }
    };
  };

  const boot = async () => {
    enabled = readEnabledState();
    const debugMode = readDebugState();

    for (const libUrl of LIB_URLS) {
      try {
        const module = await import(libUrl);
        const WebHaptics = module && module.WebHaptics;
        if (!WebHaptics) throw new Error("web-haptics module missing WebHaptics export");

        defaultPatterns = module.defaultPatterns || DEFAULT_PATTERNS;
        haptics = new WebHaptics({ showSwitch: false, debug: debugMode });
        hapticsSource = libUrl === LOCAL_LIB_URL ? "web-haptics-local" : "web-haptics-cdn";
        exposeControls(WebHaptics);
        bindGlobalHandlers();
        if (!WebHaptics.isSupported && !debugMode) {
          console.info("[R19Haptics] Device/browser vibration API unsupported. Enable debug mode with ?hapticsDebug=1 for desktop audio simulation.");
        }
        return;
      } catch (error) {
        // Try next candidate URL, then fallback.
      }
    }

    const FallbackHapticsClass = { isSupported: typeof navigator !== "undefined" && typeof navigator.vibrate === "function" };
    defaultPatterns = DEFAULT_PATTERNS;
    haptics = createFallbackHaptics();
    hapticsSource = "fallback-vibrate";
    exposeControls(FallbackHapticsClass);
    bindGlobalHandlers();
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
