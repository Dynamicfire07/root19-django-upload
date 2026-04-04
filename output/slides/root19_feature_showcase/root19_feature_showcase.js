"use strict";

const path = require("path");
const PptxGenJS = require("pptxgenjs");
const {
  autoFontSize,
  calcTextBox,
  codeToRuns,
  imageSizingContain,
  imageSizingCrop,
  safeOuterShadow,
  svgToDataUri,
  warnIfSlideElementsOutOfBounds,
  warnIfSlideHasOverlaps,
} = require("./pptxgenjs_helpers");

const pptx = new PptxGenJS();
pptx.layout = "LAYOUT_WIDE";
pptx.author = "OpenAI Codex";
pptx.company = "Root 19";
pptx.subject = "Feature showcase deck";
pptx.title = "Root 19 Feature Showcase";
pptx.lang = "en-US";
pptx.theme = {
  headFontFace: "Arial",
  bodyFontFace: "Arial",
  lang: "en-US",
};

const Sh = pptx.ShapeType;
const W = 13.333;
const H = 7.5;
const FONTS = {
  display: "Arial",
  body: "Arial",
  mono: "Consolas",
};
const C = {
  ink: "0B1220",
  midnight: "091321",
  slate: "38455A",
  steel: "6D7B91",
  cloud: "E9EEF7",
  paper: "F7F9FC",
  white: "FFFFFF",
  cyan: "4FD1FF",
  blue: "2D6BFF",
  navy: "122039",
  mint: "51D7A2",
  amber: "F4B942",
  coral: "FF7B65",
  violet: "6C7BFF",
  success: "3CB371",
  line: "D9E2F1",
  softBlue: "EAF2FF",
  softMint: "E9FBF2",
  softAmber: "FFF5DE",
  softCoral: "FFF0EC",
};

const baseDir = __dirname;
const assetsDir = path.join(baseDir, "assets");
const assets = {
  home: path.join(assetsDir, "home-default.png"),
  homeHero: path.join(assetsDir, "home-hero-crop.png"),
  questionBank: path.join(assetsDir, "question-bank-overview.png"),
  practiceDesktop: path.join(assetsDir, "practice-questions-desktop.png"),
  practiceMobile: path.join(assetsDir, "practice-questions-mobile.png"),
};

function bgSvg({ start, end, accentA, accentB, grid = true, mode = "dark" }) {
  const overlay = mode === "dark" ? "rgba(255,255,255,0.08)" : "rgba(11,18,32,0.08)";
  const stroke = mode === "dark" ? "rgba(255,255,255,0.07)" : "rgba(11,18,32,0.06)";
  return `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 900">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="${start}"/>
          <stop offset="100%" stop-color="${end}"/>
        </linearGradient>
        <radialGradient id="orbA">
          <stop offset="0%" stop-color="${accentA}" stop-opacity="0.40"/>
          <stop offset="100%" stop-color="${accentA}" stop-opacity="0"/>
        </radialGradient>
        <radialGradient id="orbB">
          <stop offset="0%" stop-color="${accentB}" stop-opacity="0.34"/>
          <stop offset="100%" stop-color="${accentB}" stop-opacity="0"/>
        </radialGradient>
      </defs>
      <rect width="1600" height="900" fill="url(#bg)"/>
      <circle cx="1360" cy="160" r="260" fill="url(#orbA)"/>
      <circle cx="220" cy="760" r="300" fill="url(#orbB)"/>
      <circle cx="1180" cy="780" r="180" fill="${overlay}"/>
      ${grid ? `
        <g stroke="${stroke}" stroke-width="1">
          <path d="M0 110 H1600"/>
          <path d="M0 790 H1600"/>
          <path d="M220 0 V900"/>
          <path d="M1380 0 V900"/>
          <path d="M0 0 L1600 900"/>
          <path d="M1600 0 L0 900"/>
        </g>
      ` : ""}
    </svg>
  `;
}

function addBackground(slide, spec) {
  slide.addImage({ data: svgToDataUri(bgSvg(spec)), x: 0, y: 0, w: W, h: H });
}

function addFooter(slide, num, tone = "dark") {
  const color = tone === "dark" ? "B8C5D9" : "6B7A90";
  slide.addText("ROOT 19 / Feature Showcase", {
    x: 0.55,
    y: 7.05,
    w: 3.4,
    h: 0.2,
    fontFace: FONTS.body,
    fontSize: 7.5,
    color,
    opacity: 0.9,
    margin: 0,
  });
  slide.addText(String(num).padStart(2, "0"), {
    x: 12.35,
    y: 7.0,
    w: 0.45,
    h: 0.22,
    fontFace: FONTS.display,
    fontSize: 10,
    bold: true,
    color,
    align: "right",
    margin: 0,
  });
}

function addPanel(slide, x, y, w, h, opts = {}) {
  slide.addShape(Sh.roundRect, {
    x,
    y,
    w,
    h,
    fill: { color: opts.fill || C.white, transparency: opts.transparency || 0 },
    line: { color: opts.line || opts.fill || C.white, transparency: opts.lineTransparency ?? 0, pt: opts.linePt || 1 },
    shadow: opts.shadow === false ? undefined : safeOuterShadow(opts.shadowColor || "10213D", opts.shadowOpacity ?? 0.18, 45, opts.shadowBlur ?? 2, opts.shadowOffset ?? 1.5),
  });
}

function addPill(slide, text, x, y, w, fill, textColor, borderColor) {
  slide.addShape(Sh.roundRect, {
    x,
    y,
    w,
    h: 0.34,
    fill: { color: fill },
    line: { color: borderColor || fill, transparency: borderColor ? 0 : 100, pt: 1 },
  });
  slide.addText(text, {
    x: x + 0.12,
    y: y + 0.06,
    w: w - 0.24,
    h: 0.18,
    fontFace: FONTS.body,
    fontSize: 8,
    bold: true,
    color: textColor,
    margin: 0,
    align: "center",
  });
}

function addTitle(slide, text, x, y, w, h, color, minSize, maxSize) {
  const opts = autoFontSize(text, FONTS.display, {
    x,
    y,
    w,
    h,
    fontSize: maxSize,
    minFontSize: minSize,
    maxFontSize: maxSize,
    bold: true,
    leading: 1.0,
    margin: 0,
    padding: 0,
    fit: "shrink",
  });
  slide.addText(text, {
    ...opts,
    color,
    bold: true,
    breakLine: false,
    valign: "mid",
  });
}

function addCopy(slide, text, x, y, w, fontSize, color, opts = {}) {
  const box = calcTextBox(fontSize, {
    text,
    w,
    fontFace: opts.fontFace || FONTS.body,
    leading: opts.leading || 1.24,
    padding: 0.02,
    margin: 0,
  });
  slide.addText(text, {
    x,
    y,
    w,
    h: Math.max(opts.h || 0, box.h),
    fontFace: opts.fontFace || FONTS.body,
    fontSize,
    color,
    margin: 0,
    bold: opts.bold || false,
    italic: opts.italic || false,
    opacity: opts.opacity,
  });
  return box.h;
}

function addDotItem(slide, text, x, y, w, color, dotColor, fontSize = 10.5) {
  slide.addShape(Sh.ellipse, {
    x,
    y: y + 0.05,
    w: 0.16,
    h: 0.16,
    fill: { color: dotColor },
    line: { color: dotColor, transparency: 100, pt: 0 },
  });
  return addCopy(slide, text, x + 0.24, y, w - 0.24, fontSize, color);
}

function addMetric(slide, x, y, w, h, label, value, meta, fill, labelColor, valueColor) {
  addPanel(slide, x, y, w, h, { fill, line: fill, shadowOpacity: 0.12, shadowBlur: 1.4, shadowOffset: 1 });
  slide.addText(label, {
    x: x + 0.18,
    y: y + 0.16,
    w: w - 0.36,
    h: 0.16,
    fontFace: FONTS.body,
    fontSize: 8,
    bold: true,
    color: labelColor,
    margin: 0,
  });
  slide.addText(value, {
    x: x + 0.18,
    y: y + 0.38,
    w: w - 0.36,
    h: 0.34,
    fontFace: FONTS.display,
    fontSize: 22,
    bold: true,
    color: valueColor,
    margin: 0,
  });
  if (meta) {
    slide.addText(meta, {
      x: x + 0.18,
      y: y + h - 0.32,
      w: w - 0.36,
      h: 0.18,
      fontFace: FONTS.body,
      fontSize: 7.5,
      color: labelColor,
      margin: 0,
    });
  }
}

function addSectionLabel(slide, text, x, y, fill, color) {
  addPill(slide, text.toUpperCase(), x, y, Math.max(1.4, text.length * 0.1 + 0.75), fill, color);
}

function addImageFrame(slide, imagePath, x, y, w, h, mode = "contain", cropArgs = null) {
  addPanel(slide, x, y, w, h, {
    fill: C.white,
    line: "D5DEEA",
    shadowOpacity: 0.18,
    shadowBlur: 2.2,
    shadowOffset: 1.6,
  });
  const inset = 0.08;
  const target = {
    x: x + inset,
    y: y + inset,
    w: w - inset * 2,
    h: h - inset * 2,
  };
  const sizing = mode === "crop"
    ? imageSizingCrop(imagePath, target.x, target.y, target.w, target.h, ...(cropArgs || []))
    : imageSizingContain(imagePath, target.x, target.y, target.w, target.h);
  slide.addImage({ path: imagePath, ...sizing });
}

function addFlowCard(slide, x, y, w, h, step, title, lines, fill, lineColor) {
  addPanel(slide, x, y, w, h, { fill, line: lineColor || fill, shadowOpacity: 0.1, shadowBlur: 1.4, shadowOffset: 1 });
  slide.addShape(Sh.ellipse, {
    x: x + 0.2,
    y: y + 0.18,
    w: 0.42,
    h: 0.42,
    fill: { color: C.ink },
    line: { color: C.ink, transparency: 100, pt: 0 },
  });
  slide.addText(step, {
    x: x + 0.2,
    y: y + 0.255,
    w: 0.42,
    h: 0.12,
    fontFace: FONTS.display,
    fontSize: 10,
    bold: true,
    color: C.white,
    align: "center",
    margin: 0,
  });
  slide.addText(title, {
    x: x + 0.72,
    y: y + 0.18,
    w: w - 0.94,
    h: 0.3,
    fontFace: FONTS.display,
    fontSize: 16,
    bold: true,
    color: C.ink,
    margin: 0,
  });
  let cursor = y + 0.64;
  lines.forEach((line) => {
    const used = addDotItem(slide, line, x + 0.22, cursor, w - 0.4, C.slate, C.blue, 9.3);
    cursor += used + 0.05;
  });
}

function addMiniBar(slide, x, y, w, label, valuePct, color) {
  slide.addText(label, {
    x,
    y,
    w,
    h: 0.16,
    fontFace: FONTS.body,
    fontSize: 8,
    bold: true,
    color: C.slate,
    margin: 0,
  });
  slide.addShape(Sh.roundRect, {
    x,
    y: y + 0.21,
    w,
    h: 0.12,
    fill: { color: C.cloud },
    line: { color: C.cloud, transparency: 100, pt: 0 },
  });
  slide.addShape(Sh.roundRect, {
    x,
    y: y + 0.21,
    w: w * valuePct,
    h: 0.12,
    fill: { color },
    line: { color, transparency: 100, pt: 0 },
  });
}

function finalizeSlide(slide) {
  warnIfSlideHasOverlaps(slide, pptx, {
    muteContainment: true,
    ignoreDecorativeShapes: true,
  });
  warnIfSlideElementsOutOfBounds(slide, pptx);
}

function coverSlide() {
  const slide = pptx.addSlide();
  addBackground(slide, {
    start: "#061224",
    end: "#132C56",
    accentA: "#2D6BFF",
    accentB: "#4FD1FF",
    mode: "dark",
  });

  addPanel(slide, 0.55, 0.62, 6.25, 5.98, {
    fill: "11203A",
    line: "2A3E63",
    transparency: 8,
    lineTransparency: 15,
    shadowColor: "040A14",
    shadowOpacity: 0.24,
    shadowBlur: 2.5,
    shadowOffset: 2,
  });

  addSectionLabel(slide, "Root 19 / Feature Showcase", 0.82, 0.9, C.softBlue, C.blue);
  addTitle(slide, "Study, compete, review, and operate from one revision workspace.", 0.82, 1.36, 5.45, 1.75, C.white, 24, 31);
  addCopy(
    slide,
    "This deck maps the real feature surface of the Django app in this repo: learner workflows, competition, community tooling, external APIs, and the staff controls that keep the system running.",
    0.84,
    3.18,
    5.2,
    11.2,
    "D7E3F6",
    { leading: 1.28 }
  );

  const pills = [
    ["Question bank", 0.84, 4.1, 1.4, C.white, C.ink, C.white],
    ["Practice studio", 2.34, 4.1, 1.52, C.softBlue, C.blue, C.softBlue],
    ["Duels + leaderboard", 3.98, 4.1, 1.9, C.softAmber, "9C6500", C.softAmber],
    ["API + staff ops", 0.84, 4.52, 1.55, C.softMint, "176347", C.softMint],
    ["Community chat", 2.53, 4.52, 1.45, "EDF0FF", C.violet, "EDF0FF"],
  ];
  pills.forEach((pill) => addPill(slide, pill[0], pill[1], pill[2], pill[3], pill[4], pill[5], pill[6]));

  addMetric(slide, 0.84, 5.14, 1.72, 1.08, "Learner flow", "6", "bank, practice, saved, stats, progress, auth", "183153", "AFC0DB", C.white);
  addMetric(slide, 2.72, 5.14, 1.72, 1.08, "Community", "3", "chat, pings, question sharing", "183153", "AFC0DB", C.white);
  addMetric(slide, 4.6, 5.14, 1.72, 1.08, "Operations", "8+", "moderation, bugs, API keys, themes", "183153", "AFC0DB", C.white);

  addImageFrame(slide, assets.homeHero, 7.02, 0.78, 5.72, 5.95, "contain");
  addPill(slide, "Homepage + product framing", 7.34, 0.95, 2.02, C.white, C.ink, C.white);

  addFooter(slide, 1, "dark");
  finalizeSlide(slide);
}

function mapSlide() {
  const slide = pptx.addSlide();
  addBackground(slide, {
    start: "#F8FBFF",
    end: "#EEF4FC",
    accentA: "#BFD8FF",
    accentB: "#D8FFF1",
    mode: "light",
  });

  addSectionLabel(slide, "Platform map", 0.6, 0.62, C.ink, C.white);
  addTitle(slide, "All major features at a glance", 0.6, 1.03, 4.8, 0.6, C.ink, 24, 28);
  addCopy(
    slide,
    "Root 19 is not just a question page. It is a full revision surface with learner, competitive, community, integration, and staff layers.",
    0.62,
    1.68,
    5.35,
    10.5,
    C.slate
  );

  const cards = [
    ["1", "Discover", ["Session + subtopic filters", "Random fallback when filters are blank"], 0.6, 2.4, C.white],
    ["2", "Practice", ["Answer-first question UI", "Timer, progress, reveal, report, share"], 3.38, 2.4, "F7FAFF"],
    ["3", "Review", ["Bookmarks + stars feed Saved Studio", "Saved queue stays in the same answer flow"], 6.16, 2.4, "F7FAFF"],
    ["4", "Track", ["Stats dashboard, streaks, avg time", "Per-session progress checklists"], 8.94, 2.4, C.white],
    ["5", "Compete", ["Party-code duels on fixed question sets", "Leaderboard plus weekly champion theme rewards"], 0.6, 4.62, C.white],
    ["6", "Connect", ["Community chat, replies, image attachments", "Question sharing and user pings"], 3.38, 4.62, "F7FAFF"],
    ["7", "Build", ["Question APIs with API keys", "Subtopic import + image/CDN fields"], 6.16, 4.62, C.white],
    ["8", "Operate", ["Question moderation, bug triage, password reset, chat lock", "Theme access, notices, API key management"], 8.94, 4.62, "F7FAFF"],
  ];
  cards.forEach((card) => addFlowCard(slide, card[3], card[4], 2.44, 1.78, card[0], card[1], card[2], card[5], "DCE7F5"));

  addFooter(slide, 2, "light");
  finalizeSlide(slide);
}

function questionBankSlide() {
  const slide = pptx.addSlide();
  addBackground(slide, {
    start: "#F6FAFF",
    end: "#EDF3FB",
    accentA: "#D7E7FF",
    accentB: "#DDFCF0",
    mode: "light",
  });

  addSectionLabel(slide, "Question selection", 0.6, 0.62, C.blue, C.white);
  addTitle(slide, "Question Bank turns the archive into a fast entry point.", 0.6, 1.0, 6.0, 0.62, C.ink, 22, 28);
  addCopy(
    slide,
    "The page is intentionally simple: choose a session, fetch matching subtopics dynamically, and launch straight into a filtered practice set.",
    0.62,
    1.65,
    5.7,
    10.6,
    C.slate
  );

  addImageFrame(slide, assets.questionBank, 0.62, 2.2, 7.2, 4.5, "contain");

  addPanel(slide, 8.18, 2.2, 4.54, 4.5, {
    fill: C.white,
    line: C.line,
    shadowOpacity: 0.14,
  });
  addPill(slide, "What this page does", 8.44, 2.42, 1.7, C.softBlue, C.blue, C.softBlue);
  let y = 2.95;
  y += addDotItem(slide, "Loads session options from the live question table and labels them by subject.", 8.44, y, 3.9, C.ink, C.blue, 10) + 0.12;
  y += addDotItem(slide, "Calls `/get-subtopics/` only after a session is selected, so the second filter stays relevant.", 8.44, y, 3.9, C.ink, C.blue, 10) + 0.12;
  y += addDotItem(slide, "Supports random behavior at two levels: everything, or random within one chosen session.", 8.44, y, 3.9, C.ink, C.blue, 10) + 0.12;
  y += addDotItem(slide, "Can surface a staff-controlled notice banner directly above the filters.", 8.44, y, 3.9, C.ink, C.blue, 10) + 0.2;

  addPanel(slide, 8.44, 5.62, 3.98, 0.74, {
    fill: C.ink,
    line: C.ink,
    shadowOpacity: 0.1,
    shadowOffset: 1,
  });
  slide.addText("/question-bank/  ->  /practice-questions/?session_code=...&subtopic=...", {
    x: 8.62,
    y: 5.87,
    w: 3.62,
    h: 0.18,
    fontFace: FONTS.mono,
    fontSize: 8.5,
    color: C.white,
    margin: 0,
  });

  addFooter(slide, 3, "light");
  finalizeSlide(slide);
}

function practiceSlide() {
  const slide = pptx.addSlide();
  addBackground(slide, {
    start: "#071220",
    end: "#15284E",
    accentA: "#3F72FF",
    accentB: "#55D8B4",
    mode: "dark",
  });

  addSectionLabel(slide, "Practice Studio", 0.6, 0.62, C.softBlue, C.blue);
  addTitle(slide, "The practice flow is the core product surface.", 0.6, 1.0, 5.5, 0.58, C.white, 22, 28);
  addCopy(
    slide,
    "It removes clutter, keeps answering front and center, and leaves the support actions close by instead of burying them in separate pages.",
    0.62,
    1.63,
    5.2,
    10.4,
    "D5E1F5"
  );

  addImageFrame(slide, assets.practiceDesktop, 0.62, 2.18, 7.22, 4.1, "contain");

  addPanel(slide, 8.15, 1.72, 2.02, 4.96, {
    fill: "152A4B",
    line: "2D4E7C",
    shadowOpacity: 0.18,
  });
  addPill(slide, "Mobile dock", 8.42, 1.95, 1.2, C.softBlue, C.blue, C.softBlue);
  addImageFrame(slide, assets.practiceMobile, 8.42, 2.3, 1.48, 3.95, "contain");

  addPanel(slide, 10.42, 1.72, 2.28, 4.96, {
    fill: "152A4B",
    line: "2D4E7C",
    shadowOpacity: 0.18,
  });
  addPill(slide, "Behaviors", 10.7, 1.95, 0.98, C.softMint, "176347", C.softMint);
  let y = 2.4;
  y += addDotItem(slide, "Guest users get a two-question preview before login prompts appear.", 10.68, y, 1.72, C.white, C.amber, 9.2) + 0.12;
  y += addDotItem(slide, "Answer feedback is instant and stays visible while the learner moves forward.", 10.68, y, 1.72, C.white, C.cyan, 9.2) + 0.12;
  y += addDotItem(slide, "Actions include star, save, reveal, send to chat, and report answer issues.", 10.68, y, 1.72, C.white, C.mint, 9.2) + 0.12;
  y += addDotItem(slide, "Keyboard support mirrors the touch controls for faster desktop drilling.", 10.68, y, 1.72, C.white, C.violet, 9.2) + 0.2;

  addMetric(slide, 10.68, 5.64, 1.72, 0.74, "Queue gate", "2", "guest preview questions", "1D385F", "B7C9E0", C.white);

  addFooter(slide, 4, "dark");
  finalizeSlide(slide);
}

function progressSlide() {
  const slide = pptx.addSlide();
  addBackground(slide, {
    start: "#F8FBFF",
    end: "#EEF4FB",
    accentA: "#CDE1FF",
    accentB: "#DCF9EB",
    mode: "light",
  });

  addSectionLabel(slide, "Retention + progress", 0.6, 0.62, C.ink, C.white);
  addTitle(slide, "Saved review, stats, checklists, and streaks keep learners coming back.", 0.6, 1.0, 6.4, 0.62, C.ink, 20, 27);
  addCopy(
    slide,
    "The product stores interaction state per user and per question, then reuses it across dashboards instead of trapping it inside one page.",
    0.62,
    1.66,
    6.05,
    10.5,
    C.slate
  );

  addPanel(slide, 0.62, 2.2, 4.52, 1.62, { fill: C.white, line: C.line, shadowOpacity: 0.12 });
  slide.addText("Personal dashboard", {
    x: 0.88,
    y: 2.44,
    w: 1.8,
    h: 0.2,
    fontFace: FONTS.body,
    fontSize: 8.5,
    bold: true,
    color: C.blue,
    margin: 0,
  });
  addMetric(slide, 0.88, 2.74, 1.02, 0.78, "Attempts", "184", "all time", C.softBlue, C.slate, C.ink);
  addMetric(slide, 2.02, 2.74, 1.02, 0.78, "Accuracy", "82%", "correct out of solved", C.softMint, C.slate, C.ink);
  addMetric(slide, 3.16, 2.74, 0.72, 0.78, "Avg", "46s", "per attempt", C.softAmber, C.slate, C.ink);
  addMetric(slide, 4.0, 2.74, 0.88, 0.78, "Streak", "7d", "5 solves/day threshold", C.softCoral, C.slate, C.ink);

  addPanel(slide, 0.62, 4.08, 4.52, 2.16, { fill: C.white, line: C.line, shadowOpacity: 0.12 });
  slide.addText("Progress checklist", {
    x: 0.88,
    y: 4.33,
    w: 2.0,
    h: 0.2,
    fontFace: FONTS.display,
    fontSize: 16,
    bold: true,
    color: C.ink,
    margin: 0,
  });
  addPill(slide, "625 / Physics", 3.62, 4.3, 1.18, C.softBlue, C.blue, C.softBlue);
  const checklist = [
    ["Motion", true],
    ["Electric fields", true],
    ["Thermal physics", false],
    ["Waves", false],
  ];
  checklist.forEach((item, idx) => {
    const rowY = 4.78 + idx * 0.33;
    slide.addShape(Sh.roundRect, {
      x: 0.9,
      y: rowY,
      w: 3.96,
      h: 0.24,
      fill: { color: idx < 2 ? "F4FAFF" : "FAFBFD" },
      line: { color: "E7EDF7", pt: 1 },
    });
    slide.addShape(Sh.ellipse, {
      x: 1.02,
      y: rowY + 0.04,
      w: 0.16,
      h: 0.16,
      fill: { color: item[1] ? C.mint : C.cloud },
      line: { color: item[1] ? C.mint : "C7D3E6", pt: 1 },
    });
    slide.addText(item[0], {
      x: 1.28,
      y: rowY + 0.045,
      w: 1.8,
      h: 0.14,
      fontFace: FONTS.body,
      fontSize: 9.2,
      bold: idx < 2,
      color: C.ink,
      margin: 0,
    });
    slide.addText(item[1] ? "completed" : "in progress", {
      x: 3.62,
      y: rowY + 0.045,
      w: 0.94,
      h: 0.14,
      fontFace: FONTS.body,
      fontSize: 8,
      color: C.steel,
      align: "right",
      margin: 0,
    });
  });

  addPanel(slide, 5.42, 2.2, 3.22, 4.04, { fill: C.white, line: C.line, shadowOpacity: 0.12 });
  slide.addText("Saved Studio", {
    x: 5.7,
    y: 2.43,
    w: 1.45,
    h: 0.2,
    fontFace: FONTS.display,
    fontSize: 16,
    bold: true,
    color: C.ink,
    margin: 0,
  });
  addCopy(slide, "Starred and bookmarked questions reappear in the same answer-first layout for focused revision.", 5.7, 2.96, 2.62, 9.2, C.slate);
  addPill(slide, "24 queued", 7.56, 2.42, 0.78, C.softBlue, C.blue, C.softBlue);

  for (let idx = 0; idx < 3; idx++) {
    const cardY = 3.58 + idx * 0.83;
    slide.addShape(Sh.roundRect, {
      x: 5.72,
      y: cardY,
      w: 2.64,
      h: 0.62,
      fill: { color: idx === 0 ? "F8FBFF" : "FBFCFE" },
      line: { color: "E6EDF8", pt: 1 },
    });
    slide.addText(`Question ${3544 + idx}`, {
      x: 5.88,
      y: cardY + 0.09,
      w: 1.0,
      h: 0.12,
      fontFace: FONTS.body,
      fontSize: 8,
      bold: true,
      color: C.steel,
      margin: 0,
    });
    slide.addShape(Sh.ellipse, {
      x: 7.14,
      y: cardY + 0.12,
      w: 0.11,
      h: 0.11,
      fill: { color: C.amber },
      line: { color: C.amber, transparency: 100, pt: 0 },
    });
    slide.addText("Star", {
      x: 7.3,
      y: cardY + 0.095,
      w: 0.34,
      h: 0.12,
      fontFace: FONTS.body,
      fontSize: 7.3,
      bold: true,
      color: "9C6500",
      margin: 0,
    });
    slide.addShape(Sh.ellipse, {
      x: 7.7,
      y: cardY + 0.12,
      w: 0.11,
      h: 0.11,
      fill: { color: C.blue },
      line: { color: C.blue, transparency: 100, pt: 0 },
    });
    slide.addText("Save", {
      x: 7.86,
      y: cardY + 0.095,
      w: 0.36,
      h: 0.12,
      fontFace: FONTS.body,
      fontSize: 7.3,
      bold: true,
      color: C.blue,
      margin: 0,
    });
    slide.addText(["Motion", "Thermal physics", "Electric fields"][idx], {
      x: 5.88,
      y: cardY + 0.39,
      w: 2.04,
      h: 0.14,
      fontFace: FONTS.display,
      fontSize: 11.2,
      bold: true,
      color: C.ink,
      margin: 0,
    });
  }

  addPanel(slide, 8.92, 2.2, 3.82, 4.04, { fill: C.white, line: C.line, shadowOpacity: 0.12 });
  slide.addText("Focus zones", {
    x: 9.2,
    y: 2.43,
    w: 1.8,
    h: 0.2,
    fontFace: FONTS.display,
    fontSize: 16,
    bold: true,
    color: C.ink,
    margin: 0,
  });
  addCopy(slide, "Top subtopics by attempts show where the learner is spending time and how accurate they are there.", 9.2, 2.72, 3.24, 9.6, C.slate);
  addMiniBar(slide, 9.2, 3.46, 2.94, "Motion", 0.84, C.blue);
  addMiniBar(slide, 9.2, 4.0, 2.94, "Electric fields", 0.67, C.mint);
  addMiniBar(slide, 9.2, 4.54, 2.94, "Waves", 0.58, C.amber);
  addMiniBar(slide, 9.2, 5.08, 2.94, "Thermal physics", 0.42, C.coral);
  addPill(slide, "recent attempts", 11.1, 5.7, 1.08, C.softBlue, C.blue, C.softBlue);
  addCopy(slide, "Recent rows also preserve whether the question was correct, solved, bookmarked, or starred.", 9.2, 5.58, 1.72, 8.8, C.slate);

  addFooter(slide, 5, "light");
  finalizeSlide(slide);
}

function competitionSlide() {
  const slide = pptx.addSlide();
  addBackground(slide, {
    start: "#0A1322",
    end: "#182841",
    accentA: "#F4B942",
    accentB: "#2D6BFF",
    mode: "dark",
  });

  addSectionLabel(slide, "Competition + motivation", 0.6, 0.62, C.softAmber, "9C6500");
  addTitle(slide, "Duels and leaderboards add pace without breaking the study model.", 0.6, 1.0, 6.2, 0.62, C.white, 22, 28);
  addCopy(slide, "Competition is implemented as a parallel surface, not a separate product: the same question archive powers it, and the same users earn the recognition.", 0.62, 1.65, 6.1, 10.4, "D5E1F5");

  addPanel(slide, 0.62, 2.2, 5.52, 4.2, {
    fill: "12233B",
    line: "284567",
    shadowColor: "050A14",
    shadowOpacity: 0.18,
  });
  slide.addText("Duels hub", {
    x: 0.9,
    y: 2.44,
    w: 1.4,
    h: 0.2,
    fontFace: FONTS.display,
    fontSize: 17,
    bold: true,
    color: C.white,
    margin: 0,
  });
  addPill(slide, "party codes", 4.84, 2.4, 0.92, C.softBlue, C.blue, C.softBlue);
  addPanel(slide, 0.9, 2.9, 2.3, 2.78, { fill: "193152", line: "2A4B79", shadow: false });
  slide.addText("Create duel", {
    x: 1.1,
    y: 3.12,
    w: 1.2,
    h: 0.16,
    fontFace: FONTS.body,
    fontSize: 10,
    bold: true,
    color: "D9E3F4",
    margin: 0,
  });
  addCopy(slide, "Pick a question scope, choose 1-20 questions, then generate a code for an opponent.", 1.1, 3.38, 1.9, 8.8, "BDD0E5");
  addPill(slide, "625 / Physics", 1.12, 4.27, 0.98, C.softBlue, C.blue, C.softBlue);
  addPill(slide, "5 questions", 2.18, 4.27, 0.86, C.softAmber, "9C6500", C.softAmber);
  addPanel(slide, 1.12, 4.8, 1.9, 0.52, { fill: C.ink, line: C.ink, shadow: false });
  slide.addText("F3G9KD", {
    x: 1.52,
    y: 4.96,
    w: 1.1,
    h: 0.14,
    fontFace: FONTS.mono,
    fontSize: 16,
    bold: true,
    color: C.white,
    margin: 0,
    align: "center",
  });

  addPanel(slide, 3.46, 2.9, 2.4, 2.78, { fill: "193152", line: "2A4B79", shadow: false });
  slide.addText("Match rules", {
    x: 3.66,
    y: 3.12,
    w: 1.2,
    h: 0.16,
    fontFace: FONTS.body,
    fontSize: 10,
    bold: true,
    color: "D9E3F4",
    margin: 0,
  });
  let duelY = 3.4;
  duelY += addDotItem(slide, "Both players get the same ordered questions.", 3.68, duelY, 1.92, C.white, C.cyan, 9.2) + 0.06;
  duelY += addDotItem(slide, "Status polling moves the duel from pending to active.", 3.68, duelY, 1.92, C.white, C.cyan, 9.2) + 0.06;
  duelY += addDotItem(slide, "Winner = most correct; time is the tie-break when both submit.", 3.68, duelY, 1.92, C.white, C.amber, 9.2) + 0.08;

  addPanel(slide, 6.48, 2.2, 6.25, 4.2, {
    fill: C.white,
    line: C.line,
    shadowOpacity: 0.14,
  });
  slide.addText("Leaderboard + champion themes", {
    x: 6.78,
    y: 2.44,
    w: 2.6,
    h: 0.2,
    fontFace: FONTS.display,
    fontSize: 17,
    bold: true,
    color: C.ink,
    margin: 0,
  });
  addCopy(slide, "Top problem solvers can see themselves in the global table, while the weekly best accuracy performer is auto-awarded champion theme access.", 6.78, 2.72, 5.2, 9.8, C.slate);

  const podium = [
    ["#1", "Areeba", "214", C.softAmber],
    ["#2", "Ibrahim", "201", "EFF3FA"],
    ["#3", "Nandini", "196", C.softCoral],
  ];
  podium.forEach((item, idx) => {
    const x = 6.86 + idx * 1.88;
    const heights = [2.26, 1.96, 1.8];
    addPanel(slide, x, 3.44 + (2.26 - heights[idx]), 1.58, heights[idx], {
      fill: item[3],
      line: item[3],
      shadowOpacity: 0.08,
    });
    slide.addText(item[0], {
      x: x + 0.16,
      y: 3.68 + (2.26 - heights[idx]),
      w: 0.34,
      h: 0.12,
      fontFace: FONTS.body,
      fontSize: 8.5,
      bold: true,
      color: C.steel,
      margin: 0,
    });
    slide.addText(item[1], {
      x: x + 0.16,
      y: 4.02 + (2.26 - heights[idx]),
      w: 1.2,
      h: 0.24,
      fontFace: FONTS.display,
      fontSize: 14,
      bold: true,
      color: C.ink,
      margin: 0,
    });
    slide.addText(item[2], {
      x: x + 0.16,
      y: 4.42 + (2.26 - heights[idx]),
      w: 1.12,
      h: 0.28,
      fontFace: FONTS.display,
      fontSize: 22,
      bold: true,
      color: C.ink,
      margin: 0,
    });
    slide.addText("solved", {
      x: x + 0.16,
      y: 4.84 + (2.26 - heights[idx]),
      w: 0.8,
      h: 0.12,
      fontFace: FONTS.body,
      fontSize: 8,
      color: C.slate,
      margin: 0,
    });
  });

  addPanel(slide, 6.82, 5.76, 5.44, 0.46, { fill: "F8FAFE", line: "E3EAF5", shadow: false });
  slide.addText("Weekly top accuracy unlocks champion mode:", {
    x: 7.02,
    y: 5.9,
    w: 2.6,
    h: 0.14,
    fontFace: FONTS.body,
    fontSize: 8.6,
    bold: true,
    color: C.slate,
    margin: 0,
  });
  slide.addText("Gold", {
    x: 10.0,
    y: 5.87,
    w: 0.42,
    h: 0.14,
    fontFace: FONTS.body,
    fontSize: 7.8,
    bold: true,
    color: "9C6500",
    margin: 0,
  });
  slide.addText("Emerald", {
    x: 10.6,
    y: 5.87,
    w: 0.62,
    h: 0.14,
    fontFace: FONTS.body,
    fontSize: 7.8,
    bold: true,
    color: "176347",
    margin: 0,
  });
  slide.addText("Sapphire", {
    x: 11.38,
    y: 5.87,
    w: 0.62,
    h: 0.14,
    fontFace: FONTS.body,
    fontSize: 7.8,
    bold: true,
    color: "4457C0",
    margin: 0,
  });

  addFooter(slide, 6, "dark");
  finalizeSlide(slide);
}

function communitySlide() {
  const slide = pptx.addSlide();
  addBackground(slide, {
    start: "#06111E",
    end: "#0F2440",
    accentA: "#4FD1FF",
    accentB: "#6C7BFF",
    mode: "dark",
  });

  addSectionLabel(slide, "Community + support", 0.6, 0.62, C.softBlue, C.blue);
  addTitle(slide, "Chat, pings, question sharing, and bug reporting close the loop.", 0.6, 1.0, 6.1, 0.62, C.white, 22, 28);
  addCopy(slide, "Learners can ask for help inside the product instead of leaving it, while support tools make it easy to report friction when something breaks.", 0.62, 1.65, 5.8, 10.4, "D5E1F5");

  addPanel(slide, 0.62, 2.18, 6.26, 4.34, {
    fill: "0B172A",
    line: "203653",
    shadowColor: "040A14",
    shadowOpacity: 0.2,
  });
  slide.addText("Community chat", {
    x: 0.92,
    y: 2.42,
    w: 1.8,
    h: 0.2,
    fontFace: FONTS.display,
    fontSize: 17,
    bold: true,
    color: C.white,
    margin: 0,
  });
  addPill(slide, "notifications", 5.36, 2.39, 1.0, C.softAmber, "9C6500", C.softAmber);
  slide.addShape(Sh.roundRect, {
    x: 0.94,
    y: 2.88,
    w: 5.62,
    h: 2.82,
    fill: { color: "0F213A" },
    line: { color: "1D365A", pt: 1 },
  });

  const bubbles = [
    { x: 1.18, y: 3.18, w: 2.6, h: 0.7, self: false, name: "Areeba", body: "Can someone sanity-check the motion question I just shared?" },
    { x: 2.84, y: 4.0, w: 3.2, h: 0.74, self: true, name: "Ibrahim", body: "I think the answer is B because the acceleration stays constant." },
    { x: 1.18, y: 4.92, w: 2.8, h: 0.62, self: false, name: "Nandini", body: "Pinged the group and attached the screenshot." },
  ];
  bubbles.forEach((bubble) => {
    slide.addShape(Sh.roundRect, {
      x: bubble.x,
      y: bubble.y,
      w: bubble.w,
      h: bubble.h,
      fill: { color: bubble.self ? "2A6DFF" : "142843" },
      line: { color: bubble.self ? "2A6DFF" : "223D63", pt: 1 },
    });
    slide.addText(bubble.name, {
      x: bubble.x + 0.12,
      y: bubble.y + 0.1,
      w: bubble.w - 0.24,
      h: 0.12,
      fontFace: FONTS.body,
      fontSize: 7.6,
      bold: true,
      color: C.white,
      margin: 0,
    });
    slide.addText(bubble.body, {
      x: bubble.x + 0.12,
      y: bubble.y + 0.26,
      w: bubble.w - 0.24,
      h: 0.26,
      fontFace: FONTS.body,
      fontSize: 8.3,
      color: "E6EEFA",
      margin: 0,
    });
  });
  addPill(slide, "Reply", 4.66, 3.17, 0.56, "24476F", C.white, "24476F");
  addPill(slide, "Ping", 5.26, 3.17, 0.48, "24476F", C.white, "24476F");
  addPill(slide, "Image attached", 4.1, 5.0, 1.18, C.softBlue, C.blue, C.softBlue);
  addPill(slide, "question shared from practice", 3.56, 5.86, 1.92, C.softMint, "176347", C.softMint);

  addPanel(slide, 7.18, 2.18, 5.54, 1.28, { fill: C.white, line: C.line, shadowOpacity: 0.12 });
  slide.addText("Report a bug", {
    x: 7.46,
    y: 2.42,
    w: 1.4,
    h: 0.18,
    fontFace: FONTS.display,
    fontSize: 15,
    bold: true,
    color: C.ink,
    margin: 0,
  });
  addCopy(slide, "Structured form collects title, description, reproduction steps, severity, contact email, and an optional screenshot upload.", 7.46, 2.72, 4.7, 9.4, C.slate);

  addPanel(slide, 7.18, 3.66, 2.56, 2.86, { fill: C.white, line: C.line, shadowOpacity: 0.12 });
  slide.addText("User help paths", {
    x: 7.46,
    y: 3.92,
    w: 1.3,
    h: 0.18,
    fontFace: FONTS.display,
    fontSize: 15,
    bold: true,
    color: C.ink,
    margin: 0,
  });
  let helpY = 4.26;
  helpY += addDotItem(slide, "Password reset requests can be queued for staff approval.", 7.46, helpY, 1.94, C.ink, C.blue, 9.1) + 0.08;
  helpY += addDotItem(slide, "Change password is available from the signed-in menu.", 7.46, helpY, 1.94, C.ink, C.blue, 9.1) + 0.08;
  helpY += addDotItem(slide, "Legal and changelog pages round out the support surface.", 7.46, helpY, 1.94, C.ink, C.blue, 9.1) + 0.08;

  addPanel(slide, 10.08, 3.66, 2.64, 2.86, { fill: C.white, line: C.line, shadowOpacity: 0.12 });
  slide.addText("Chat governance", {
    x: 10.36,
    y: 3.92,
    w: 1.5,
    h: 0.18,
    fontFace: FONTS.display,
    fontSize: 15,
    bold: true,
    color: C.ink,
    margin: 0,
  });
  addCopy(slide, "Staff can globally lock chat behind a password gate for non-admin users when moderation needs tighten.", 10.36, 4.26, 2.08, 9.1, C.slate);
  addPill(slide, "chat lock", 10.36, 5.38, 0.78, C.softAmber, "9C6500", C.softAmber);
  addPill(slide, "staff delete controls", 11.22, 5.38, 1.22, C.softBlue, C.blue, C.softBlue);

  addFooter(slide, 7, "dark");
  finalizeSlide(slide);
}

function apiSlide() {
  const slide = pptx.addSlide();
  addBackground(slide, {
    start: "#F7FBFF",
    end: "#EEF5FC",
    accentA: "#D4E4FF",
    accentB: "#DDF8F0",
    mode: "light",
  });

  addSectionLabel(slide, "API + integrations", 0.6, 0.62, C.blue, C.white);
  addTitle(slide, "A documented API lets other sites consume the question archive.", 0.6, 1.0, 6.1, 0.62, C.ink, 21, 27);
  addCopy(slide, "The app exposes question listing, question detail, and subtopic import endpoints behind managed API keys and multiple auth header styles.", 0.62, 1.66, 6.2, 10.5, C.slate);

  addPanel(slide, 0.62, 2.18, 5.58, 4.38, { fill: "0E1627", line: "22314B", shadowOpacity: 0.14 });
  slide.addText("Sample request", {
    x: 0.92,
    y: 2.42,
    w: 1.3,
    h: 0.18,
    fontFace: FONTS.display,
    fontSize: 16,
    bold: true,
    color: C.white,
    margin: 0,
  });
  const code = [
    "curl -H \"X-API-Key: r19_xxx\" \\",
    "  \"https://app.root19.com/api/questions/?subject=Physics&session=May/June&limit=10&include_image_base64=0\"",
  ].join("\n");
  slide.addText(codeToRuns(code, "bash"), {
    x: 0.92,
    y: 2.82,
    w: 4.96,
    h: 1.18,
    margin: 0.08,
    breakLine: false,
    fill: { color: "132038" },
    line: { color: "243651", pt: 1 },
  });

  addPill(slide, "X-API-Key header", 0.92, 4.18, 1.16, C.softBlue, C.blue, C.softBlue);
  addPill(slide, "Bearer token", 2.18, 4.18, 1.04, C.softMint, "176347", C.softMint);
  addPill(slide, "URL api_key", 3.34, 4.18, 0.94, C.softAmber, "9C6500", C.softAmber);

  addPanel(slide, 0.92, 4.72, 4.96, 1.48, { fill: "132038", line: "243651", shadow: false });
  slide.addText("Exposed endpoints", {
    x: 1.14,
    y: 4.95,
    w: 1.2,
    h: 0.16,
    fontFace: FONTS.body,
    fontSize: 9,
    bold: true,
    color: "DDE8FA",
    margin: 0,
  });
  addDotItem(slide, "GET /api/questions/ -> paginated archive search with normalized helper fields", 1.14, 5.22, 4.42, C.white, C.cyan, 8.9);
  addDotItem(slide, "GET /api/questions/<question_id>/ and GET /api/subtopics/ -> detail + import workflows", 1.14, 5.55, 4.42, C.white, C.cyan, 8.9);

  addPanel(slide, 6.54, 2.18, 3.06, 4.38, { fill: C.white, line: C.line, shadowOpacity: 0.12 });
  slide.addText("Filters + response shape", {
    x: 6.82,
    y: 2.42,
    w: 1.8,
    h: 0.18,
    fontFace: FONTS.display,
    fontSize: 16,
    bold: true,
    color: C.ink,
    margin: 0,
  });
  let filterY = 2.78;
  [
    "subject / session_code",
    "session / year / paper / variant",
    "subtopic / question_type / answer",
    "q search / limit / offset / order_by / sort",
    "include_image_base64 switch",
  ].forEach((item) => {
    filterY += addDotItem(slide, item, 6.82, filterY, 2.36, C.ink, C.blue, 9.1) + 0.05;
  });
  addPanel(slide, 6.84, 5.14, 2.5, 1.05, { fill: C.softBlue, line: C.softBlue, shadow: false });
  slide.addText("Normalized helper fields also include `image_link`, `image_src`, `question`, and `subject`.", {
    x: 7.0,
    y: 5.34,
    w: 2.18,
    h: 0.46,
    fontFace: FONTS.body,
    fontSize: 8.8,
    color: C.ink,
    margin: 0,
  });

  addPanel(slide, 9.92, 2.18, 2.8, 4.38, { fill: C.white, line: C.line, shadowOpacity: 0.12 });
  slide.addText("Key management + image delivery", {
    x: 10.2,
    y: 2.42,
    w: 2.1,
    h: 0.32,
    fontFace: FONTS.display,
    fontSize: 16,
    bold: true,
    color: C.ink,
    margin: 0,
  });
  addCopy(slide, "Staff can create limited or unlimited keys, track usage, reset counts, and regenerate compromised credentials.", 10.2, 2.9, 2.22, 9.1, C.slate);
  addPill(slide, "limited keys", 10.2, 3.9, 0.88, C.softAmber, "9C6500", C.softAmber);
  addPill(slide, "usage count", 11.16, 3.9, 0.82, C.softBlue, C.blue, C.softBlue);
  addPill(slide, "active / inactive", 10.2, 4.28, 1.1, C.softMint, "176347", C.softMint);
  addCopy(slide, "Question images can also be served from Supabase Storage, with `image_url` and `image_link` helping clients avoid large inline payloads.", 10.2, 4.82, 2.14, 9.1, C.slate);

  addFooter(slide, 8, "light");
  finalizeSlide(slide);
}

function staffSlide() {
  const slide = pptx.addSlide();
  addBackground(slide, {
    start: "#F8FBFF",
    end: "#EFF4FB",
    accentA: "#D6E4FF",
    accentB: "#FFF1D6",
    mode: "light",
  });

  addSectionLabel(slide, "Staff control center", 0.6, 0.62, C.ink, C.white);
  addTitle(slide, "Operational tools are unusually broad for a study app.", 0.6, 1.0, 6.2, 0.62, C.ink, 22, 28);
  addCopy(slide, "The admin surface covers content quality, support queues, theming access, chat governance, and external integrations.", 0.62, 1.66, 6.0, 10.5, C.slate);

  const tools = [
    ["Question tester", "Search by ID or extracted text, preview the image, and validate submitted answers."],
    ["Question reports", "Review answer disputes, compare suggested vs live answers, and resolve moderation states."],
    ["Bug reports", "Triage severity-tagged reports, screenshots, statuses, and reopen/close flows."],
    ["Password requests", "Approve reset requests and jump directly into the reset tool for the target email."],
    ["Theme access", "Grant or revoke champion themes and preview who receives weekly recognition."],
    ["Question notice", "Publish a banner on the question bank when there is a service or content notice."],
    ["API key panel", "Generate, regenerate, deactivate, or reset usage on external integration keys."],
    ["Chat lock", "Gate community chat behind a staff-controlled password without removing the feature entirely."],
  ];

  tools.forEach((tool, idx) => {
    const col = idx % 4;
    const row = Math.floor(idx / 4);
    const x = 0.62 + col * 3.12;
    const y = 2.32 + row * 1.9;
    addPanel(slide, x, y, 2.82, 1.54, { fill: C.white, line: C.line, shadowOpacity: 0.1 });
    slide.addShape(Sh.ellipse, {
      x: x + 0.18,
      y: y + 0.18,
      w: 0.28,
      h: 0.28,
      fill: { color: [C.blue, C.coral, C.amber, C.violet, C.mint, C.blue, C.ink, C.coral][idx] },
      line: { color: [C.blue, C.coral, C.amber, C.violet, C.mint, C.blue, C.ink, C.coral][idx], transparency: 100, pt: 0 },
    });
    slide.addText(tool[0], {
      x: x + 0.56,
      y: y + 0.18,
      w: 1.9,
      h: 0.2,
      fontFace: FONTS.display,
      fontSize: 13,
      bold: true,
      color: C.ink,
      margin: 0,
    });
    addCopy(slide, tool[1], x + 0.2, y + 0.56, 2.38, 8.5, C.slate);
  });

  addPanel(slide, 0.62, 6.28, 12.1, 0.55, { fill: "122039", line: "122039", shadow: false });
  slide.addText("The result is a codebase with both learner-facing polish and production-minded guardrails.", {
    x: 0.92,
    y: 6.45,
    w: 6.8,
    h: 0.14,
    fontFace: FONTS.body,
    fontSize: 9.8,
    bold: true,
    color: C.white,
    margin: 0,
  });
  addPill(slide, "moderation", 8.52, 6.38, 0.76, C.softBlue, C.blue, C.softBlue);
  addPill(slide, "support", 9.38, 6.38, 0.62, C.softAmber, "9C6500", C.softAmber);
  addPill(slide, "governance", 10.08, 6.38, 0.82, C.softMint, "176347", C.softMint);
  addPill(slide, "ops", 11.0, 6.38, 0.42, C.softCoral, C.coral, C.softCoral);

  addFooter(slide, 9, "light");
  finalizeSlide(slide);
}

function summarySlide() {
  const slide = pptx.addSlide();
  addBackground(slide, {
    start: "#061223",
    end: "#132B55",
    accentA: "#4FD1FF",
    accentB: "#F4B942",
    mode: "dark",
  });

  addSectionLabel(slide, "Summary", 0.6, 0.62, C.softBlue, C.blue);
  addTitle(slide, "Root 19 already behaves like a full revision platform.", 0.6, 1.0, 6.3, 0.62, C.white, 23, 29);
  addCopy(
    slide,
    "Its strongest story is the continuity between surfaces: discover questions, practice in a focused screen, save what matters, track performance, compete with others, and back it all with real operational tooling.",
    0.62,
    1.67,
    6.2,
    10.8,
    "D5E1F5"
  );

  const summary = [
    ["Learner flow", "Question Bank, Practice Studio, Saved Studio, progress checklists, stats dashboards, streaks."],
    ["Social + pace", "Community chat, question sharing, user pings, duels, leaderboard, champion themes."],
    ["Developer surface", "Managed API keys, question endpoints, subtopic import, normalized image fields, CDN-friendly responses."],
    ["Operational maturity", "Question moderation, bug triage, password reset workflow, notices, theme access, chat locking."],
  ];
  summary.forEach((item, idx) => {
    const x = 0.62 + (idx % 2) * 6.1;
    const y = 2.72 + Math.floor(idx / 2) * 1.7;
    addPanel(slide, x, y, 5.72, 1.38, {
      fill: "132644",
      line: "2A4770",
      shadowColor: "040A14",
      shadowOpacity: 0.18,
    });
    slide.addText(item[0], {
      x: x + 0.24,
      y: y + 0.22,
      w: 2.2,
      h: 0.2,
      fontFace: FONTS.display,
      fontSize: 15,
      bold: true,
      color: C.white,
      margin: 0,
    });
    addCopy(slide, item[1], x + 0.24, y + 0.56, 5.12, 9.2, "D7E3F6");
  });

  addPanel(slide, 0.62, 6.32, 12.1, 0.48, {
    fill: "EDF5FF",
    line: "EDF5FF",
    shadow: false,
  });
  slide.addText("Showcase takeaway: the repo supports a polished presentation for students, plus the backstage tooling needed to run it seriously.", {
    x: 0.92,
    y: 6.47,
    w: 10.8,
    h: 0.14,
    fontFace: FONTS.body,
    fontSize: 9.6,
    bold: true,
    color: C.ink,
    margin: 0,
  });

  addFooter(slide, 10, "dark");
  finalizeSlide(slide);
}

async function main() {
  coverSlide();
  mapSlide();
  questionBankSlide();
  practiceSlide();
  progressSlide();
  competitionSlide();
  communitySlide();
  apiSlide();
  staffSlide();
  summarySlide();

  await pptx.writeFile({ fileName: path.join(baseDir, "root19_feature_showcase.pptx") });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});