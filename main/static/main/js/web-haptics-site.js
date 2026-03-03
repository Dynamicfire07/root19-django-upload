/* Root19 global haptics layer powered by web-haptics (https://haptics.lochie.me) */
(function () {
  if (window.__R19_HAPTICS_BOOTSTRAPPED__) return;
  window.__R19_HAPTICS_BOOTSTRAPPED__ = true;

  const LIB_URL = "https://cdn.jsdelivr.net/npm/web-haptics@0.0.6/dist/index.mjs";
  const STORAGE_KEY = "r19_haptics_enabled";
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

  const now = () => Date.now();

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

  const trigger = (pattern, minGapMs = 50, options) => {
    if (!enabled || !haptics) return;
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
      }
    };
  };

  const boot = async () => {
    enabled = readEnabledState();

    try {
      const importer = new Function("url", "return import(url);");
      const module = await importer(LIB_URL);
      const WebHaptics = module && module.WebHaptics;
      if (!WebHaptics) return;

      defaultPatterns = module.defaultPatterns || {};
      haptics = new WebHaptics({ showSwitch: false });
      exposeControls(WebHaptics);

      if (!WebHaptics.isSupported) return;
      bindGlobalHandlers();
    } catch (error) {
      // Fail quietly on unsupported browsers or blocked CDN requests.
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
