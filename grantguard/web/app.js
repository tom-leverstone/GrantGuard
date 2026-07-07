// Client-side app: boots a scan, renders a persistent sidebar with Overview and
// detail/list panes, and drives the select-and-remove flow for flagged grants.

const $ = (s) => document.querySelector(s);

// Per-session access token, carried in the launch URL (?t=…). Sent on every API
// call so co-located local users can't read findings or trigger writes.
const API_TOKEN = new URLSearchParams(location.search).get("t") || "";
const apiGet = (url) => fetch(url, { headers: { "X-GrantGuard-Token": API_TOKEN } });
const fetchAudit = () => apiGet("/api/audit").then((r) => r.json());

const TIER = {
  TOSS: { label: "Remove", badge: "red" },
  SIDEYE: { label: "Review", badge: "orange" },
  VIP: { label: "Keep", badge: "green" },
};
const REASONS = {
  SECRET: "Inline credentials",
  KEYCHAIN: "Credential-store access",
  DESTRUCTIVE: "Destructive wildcards",
  REMOTE_PUSH: "Remote push",
  OVERBROAD: "Overly broad wildcards",
  SAFE: "Scoped / read-only",
};
const svgIcon = (paths) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
// parse static, trusted icon markup into an SVG node (DOM-safe; no innerHTML)
const svgEl = (markup) => new DOMParser().parseFromString(markup, "image/svg+xml").documentElement;
const REASON_SVG = {
  SECRET: svgIcon(
    `<path d="M5 13a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-6z"/><path d="M11 16a1 1 0 1 0 2 0a1 1 0 0 0 -2 0"/><path d="M8 11v-4a4 4 0 1 1 8 0v4"/>`,
  ),
  KEYCHAIN: svgIcon(
    `<path d="M16.555 3.843l3.602 3.602a2.877 2.877 0 0 1 0 4.069l-2.643 2.643a2.877 2.877 0 0 1 -4.069 0l-.301 -.301l-6.558 6.558a2 2 0 0 1 -1.239 .578l-.175 .008h-1.171a1 1 0 0 1 -.993 -.883l-.007 -.117v-1.171a2 2 0 0 1 .467 -1.284l.119 -.13l.13 -.119l6.558 -6.558l-.301 -.301a2.877 2.877 0 0 1 0 -4.069l2.643 -2.643a2.877 2.877 0 0 1 4.069 0z"/><path d="M15 9h.01"/>`,
  ),
  DESTRUCTIVE: svgIcon(
    `<circle cx="10.5" cy="14" r="7"/><path d="M15.8 8.7c1.5 -1.5 2.6 -2.6 3.6 -3.6"/><path d="M19 4.1l.7 1.2M21.6 4.2l-1.2 .7M21.4 6.7l-1.2 -.4"/>`,
  ),
  REMOTE_PUSH: svgIcon(
    `<path d="M12 15v-9"/><path d="M8.5 9.5l3.5 -3.5l3.5 3.5"/><path d="M5 19h14"/>`,
  ),
  OVERBROAD: svgIcon(
    `<path d="M12 4v16"/><path d="M4.93 7.5l14.14 9"/><path d="M19.07 7.5l-14.14 9"/>`,
  ),
};
const REASON_ORDER = ["SECRET", "KEYCHAIN", "DESTRUCTIVE", "REMOTE_PUSH", "OVERBROAD", "SAFE"];
const TIER_LABEL = { TOSS: "Flagged to remove", SIDEYE: "To review", VIP: "Safe to keep" };
// Pre-parsed; cloneNode(true) per use so the same node isn't inserted twice.
const CHEVRON_EL = svgEl(svgIcon(`<path d="M9 6l6 6l-6 6"/>`));

// Brand glyphs (filled, inherit currentColor) for the share buttons.
const X_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>`;
const LINKEDIN_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>`;

const REPO_URL = "https://github.com/VantaInc/grantguard";

// ── Global state ─────────────────────────────────────────────────────────────
const state = {
  data: null,
  view: "overview", // "overview" | "detail"
  activeIdx: "all",
  filter: { kind: "all", value: null },
  selected: new Set(), // composite keys: `${sourceIdx} ${rule}`
  // Session narrative for the share reward: how many were flagged at first scan,
  // and how many the user has since removed (one held a live credential).
  session: { found: null, removed: 0, secretRemoved: false },
};

// Single mutation point: accepts a patch object to merge, or a callback that
// mutates state in place (for updates that need to read current state first).
// Every state change re-renders, so renderAll is never called directly elsewhere.
function setState(patchOrFn) {
  if (typeof patchOrFn === "function") patchOrFn(state);
  else Object.assign(state, patchOrFn);
  renderAll(state);
}

// ── Utilities ─────────────────────────────────────────────────────────────────
const key = (sidx, rule) => sidx + " " + rule;
const parseKey = (k) => {
  const i = k.indexOf(" ");
  return [+k.slice(0, i), k.slice(i + 1)];
};
const basename = (p) => p.split("/").pop();
function shortFolder(p, home) {
  const dir = p.replace(/\/[^/]*$/, "");
  return home && dir.startsWith(home) ? "~" + dir.slice(home.length) : dir;
}

// DOM builder — values go in via textContent/setAttribute, never parsed as HTML.
function h(tag, attrs = {}, children = []) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k === "style") Object.assign(n.style, v);
    else if (k === "checked" || k === "disabled") n[k] = !!v;
    else if (k === "onclick") n.onclick = v;
    else n.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null || c === false) continue;
    n.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return n;
}

// ── Aggregates (pure: derive from arguments, never read module state) ──────────
function allItems(data) {
  return data.sources.flatMap((s, si) => s.items.map((it) => ({ ...it, _sidx: si, _src: s })));
}
function scopeItems(data, idx) {
  if (idx === "all") return allItems(data);
  return data.sources[idx].items.map((it) => ({
    ...it,
    _sidx: idx,
    _src: data.sources[idx],
  }));
}
function visibleItems(data, idx, filter) {
  const items = scopeItems(data, idx);
  if (filter.kind === "all") return items;
  if (filter.kind === "tier") return items.filter((i) => i.tier === filter.value);
  return items.filter((i) => i.reason === filter.value);
}
const reviewedTotal = (data) => data.sources.reduce((n, s) => n + s.total, 0);
const flaggedTotal = (data) => allItems(data).filter((i) => i.recommend_remove).length;
const countReason = (items, r) => items.filter((i) => i.reason === r).length;
const countTier = (items, t) => items.filter((i) => i.tier === t).length;

function shareCaption({ found, removed }) {
  const n = found || 0;
  return removed > 0
    ? `I used @vanta's GrantGuard to audit my Claude Code permissions — found ${n} risky "always allow" grant${n === 1 ? "" : "s"} and removed ${removed}, keeping my AI agent's access scoped and safe.`
    : `I used @vanta's GrantGuard to audit my Claude Code permissions and found no risky standing grants — my agent's access is scoped and safe.`;
}

// ── Shared bar + legend helpers ───────────────────────────────────────────────
const BAR_TIERS = [
  { cls: "red", label: "Flagged to remove ", key: "toss" },
  { cls: "orange", label: "To review ", key: "side" },
  { cls: "green", label: "Safe to keep ", key: "vip" },
];
function fillBar(container, toss, side, vip, tot) {
  const counts = { toss, side, vip };
  container.replaceChildren(
    ...BAR_TIERS.filter(({ key }) => counts[key] > 0).map(({ cls, key }) =>
      h("span", { class: "seg " + cls, style: { width: (counts[key] / tot) * 100 + "%" } }),
    ),
  );
}
function fillLegend(container, toss, side, vip) {
  const counts = { toss, side, vip };
  container.replaceChildren(
    ...BAR_TIERS.filter(({ key }) => counts[key] > 0).map(({ cls, label, key }) =>
      h("span", {}, [h("i", { class: cls }), label, h("b", { text: String(counts[key]) })]),
    ),
  );
}

// ── Shared nav item builders ──────────────────────────────────────────────────
function navSection(title) {
  return h("div", { class: "nav-section", text: title });
}

function navItem({ dot, label, sub, trail, active, onClick }) {
  return h("div", { class: "nav-item" + (active ? " active" : ""), onclick: onClick }, [
    h("span", { class: "dot " + dot }),
    h("span", { class: "label" }, [label, sub ? h("small", { text: sub }) : null]),
    trail !== "" && trail != null ? h("span", { class: "count", text: String(trail) }) : null,
  ]);
}

// ── emit helper (bubbles to document) ────────────────────────────────────────
class GgEvent extends CustomEvent {
  constructor(type, detail) {
    super(type, { bubbles: true, composed: true, detail });
  }
}

function emit(el, type, detail) {
  el.dispatchEvent(new GgEvent(type, detail));
}

// ── <gg-nav> ─────────────────────────────────────────────────────────────────
class GgNav extends HTMLElement {
  update({ data, view: v, activeIdx: ai, filter: f }) {
    this._data = data;
    this._view = v;
    this._activeIdx = ai;
    this._filter = f;
    this._render();
  }

  _render() {
    if (!this._data) return;
    const { _data: data, _view: v, _activeIdx: ai, _filter: f } = this;
    this.replaceChildren();

    const flagged = flaggedTotal(data);
    this.append(
      navItem({
        dot: flagged ? "orange" : "green",
        label: "Summary",
        trail: flagged || "",
        active: v === "overview",
        onClick: () => emit(this, "gg-view-change", "overview"),
      }),
    );

    this.append(navSection("Sources"));
    this.append(
      navItem({
        dot: "blue",
        label: "All sources",
        sub: `${data.sources.length} files`,
        trail: reviewedTotal(data),
        active: v === "detail" && ai === "all",
        onClick: () => emit(this, "gg-scope-change", "all"),
      }),
    );
    data.sources.forEach((s, i) => {
      this.append(
        navItem({
          dot: "blue",
          label: shortFolder(s.path, data.home) + (s.editable ? "" : " 🔒"),
          sub: `${basename(s.path)} · ${s.label}`,
          trail: s.total,
          active: v === "detail" && ai === i,
          onClick: () => emit(this, "gg-scope-change", i),
        }),
      );
    });

    const items = scopeItems(data, ai);
    this.append(navSection("Filter"));
    const tierItem = (val, label, dot) =>
      navItem({
        dot,
        label,
        trail: countTier(items, val),
        active: v === "detail" && f.kind === "tier" && f.value === val,
        onClick: () => emit(this, "gg-filter-change", { kind: "tier", value: val }),
      });
    this.append(
      navItem({
        dot: "blue",
        label: "All rules",
        trail: items.length,
        active: v === "detail" && f.kind === "all",
        onClick: () => emit(this, "gg-filter-change", { kind: "all", value: null }),
      }),
    );
    this.append(tierItem("TOSS", "Flagged to remove", "red"));
    this.append(tierItem("SIDEYE", "To review", "orange"));
    this.append(tierItem("VIP", "Safe to keep", "green"));

    this.append(navSection("Categories"));
    for (const r of REASON_ORDER) {
      const c = countReason(items, r);
      if (!c) continue;
      const dot = r === "SAFE" ? "green" : r === "OVERBROAD" ? "orange" : "red";
      this.append(
        navItem({
          dot,
          label: REASONS[r],
          trail: c,
          active: v === "detail" && f.kind === "reason" && f.value === r,
          onClick: () => emit(this, "gg-filter-change", { kind: "reason", value: r }),
        }),
      );
    }
  }
}
customElements.define("gg-nav", GgNav);

// ── <gg-scope> ───────────────────────────────────────────────────────────────
// Session scan-scope picker. Draft edits live in the element; only "Rescan"
// emits gg-scope-apply, and the draft re-syncs when the server-side scope
// actually changes so re-renders never clobber a path the user is mid-typing.
// The depth select maps 1:1 onto the server modes so every single-target scope
// round-trips exactly (a deep scan re-applies as a deep scan).
const BROAD_SCAN_WARNING =
  "Broad scan sweeps your home folder and common project locations for Claude settings files. It can take a while.\n\nNothing is changed by scanning — you still review before any removal.";

const SCOPE_SUMMARY = {
  user: () => "user settings",
  "deep-scan": (t) => (t.length ? `deep discovery · ${t.join(", ")}` : "broad scan"),
  scan: (t) => `shallow discovery · ${t.join(", ")}`,
  targets: (t) => `exact · ${t.join(", ")}`,
};

class GgScope extends HTMLElement {
  connectedCallback() {
    this._syncedData = null;
    this._lastScope = null;

    this._pathInput = h("input", {
      class: "scope-path",
      type: "text",
      spellcheck: "false",
      placeholder: "/path/to/repo or settings.json",
      "aria-label": "Directory or file to audit",
    });
    this._pathInput.oninput = () => this._syncVisibility();
    this._depthSel = h("select", { class: "scope-depth", "aria-label": "Discovery depth" }, [
      h("option", { value: "scan", text: "Discover settings beneath it" }),
      h("option", { value: "deep-scan", text: "Discover deeply beneath it" }),
      h("option", { value: "targets", text: "Audit exactly this path" }),
    ]);

    this._radios = {};
    const radio = (val, label, sub, extra = null) => {
      const inp = h("input", { type: "radio", name: "scope-mode", value: val });
      inp.onchange = () => this._syncVisibility();
      this._radios[val] = inp;
      return h("div", { class: "scope-opt" }, [
        h("label", { class: "scope-choice" }, [
          inp,
          h("span", { class: "label" }, [label, sub ? h("small", { text: sub }) : null]),
        ]),
        extra,
      ]);
    };

    this._pathExtra = h("div", { class: "scope-path-box hidden" }, [
      this._pathInput,
      this._depthSel,
    ]);
    this._active = h("div", { class: "scope-active" });
    this._error = h("p", { class: "scope-error hidden" });
    this._applyBtn = h("button", {
      class: "btn scope-apply",
      text: "Rescan with this scope",
      onclick: () => this._onApply(),
    });

    this.replaceChildren(
      navSection("Scan scope"),
      h("div", { class: "scope-box" }, [
        this._active,
        radio("user", "User settings", "your Claude Code defaults"),
        radio("path", "Specific directory or file", null, this._pathExtra),
        radio("broad", "Broad scan", "home + common project folders"),
        this._applyBtn,
        this._error,
      ]),
    );
  }

  _mode() {
    const checked = Object.values(this._radios).find((r) => r.checked);
    return checked?.value ?? "user";
  }

  _syncVisibility() {
    const mode = this._mode();
    this._pathExtra.classList.toggle("hidden", mode !== "path");
    this._applyBtn.disabled = mode === "path" && !this._pathInput.value.trim();
  }

  _onApply() {
    const mode = this._mode();
    // The broad-scan confirm lives with the component that knows what "broad"
    // means, so the gate can't drift out of sync with the mode definitions.
    if (mode === "broad" && !confirm(BROAD_SCAN_WARNING)) return;
    // The path is taken verbatim — one target per rescan, so commas in real
    // directory names survive; multiple targets remain a CLI-launch feature.
    const detail =
      mode === "user"
        ? { mode: "user", targets: [] }
        : mode === "broad"
          ? { mode: "deep-scan", targets: [] }
          : { mode: this._depthSel.value, targets: [this._pathInput.value.trim()] };
    emit(this, "gg-scope-apply", detail);
  }

  showError(message) {
    this._error.classList.toggle("hidden", !message);
    this._error.textContent = message ?? "";
  }

  _syncDraft(scope) {
    if (scope.targets.length > 1) return; // single-path draft can't hold it; the Active line stays truthful
    const radio = scope.mode === "user" ? "user" : scope.targets.length === 0 ? "broad" : "path";
    this._radios[radio].checked = true;
    if (radio === "path") {
      this._pathInput.value = scope.targets[0];
      this._depthSel.value = scope.mode;
    }
    this._syncVisibility();
  }

  update({ data }) {
    if (!data || !data.scope) return;
    this._active.textContent = "Active: " + SCOPE_SUMMARY[data.scope.mode](data.scope.targets);
    if (data === this._syncedData) return; // same fetch → same scope; keep any draft edits
    this._syncedData = data;
    const key = JSON.stringify(data.scope);
    if (key !== this._lastScope) {
      this._lastScope = key;
      this._syncDraft(data.scope);
    }
  }
}
customElements.define("gg-scope", GgScope);

// ── <gg-overview> ────────────────────────────────────────────────────────────
class GgOverview extends HTMLElement {
  connectedCallback() {
    this.replaceChildren(
      h("div", { class: "ov" }, [
        h("div", { class: "ov-head" }, [
          h("span", { class: "ov-dot", id: "_leadDot" }),
          h("div", {}, [h("h1", { id: "_leadTitle" }), h("p", { id: "_leadSub" })]),
        ]),
        h("div", { class: "box ov-summary" }, [
          h("div", { class: "sumbar", id: "_lSumBar" }),
          h("div", { class: "legend", id: "_lLegend" }),
        ]),
        h("div", { id: "_findingsBlock" }, [
          h("div", { class: "group-label", text: "What we found" }),
          h("div", { class: "box", id: "_findingList" }),
        ]),
        h("div", { class: "ov-actions", id: "_nextSteps" }),
        h("div", { class: "share", id: "_share" }),
      ]),
    );
  }

  update({ data, session }) {
    this._data = data;
    this._session = session;
    this._render();
  }

  _q(id) {
    return this.querySelector("#" + id);
  }

  _render() {
    if (!this._data) return;
    const items = allItems(this._data);
    const flagged = items.filter((i) => i.recommend_remove).length;
    const files = this._data.sources.length;
    const reviewed = reviewedTotal(this._data);
    const clean = flagged === 0;

    this._q("_leadDot").className = "ov-dot " + (clean ? "ok" : "warn");
    this._q("_leadTitle").textContent =
      files === 0
        ? "No settings found"
        : clean
          ? "No risky permissions found"
          : `${flagged} permission${flagged === 1 ? "" : "s"} worth a closer look`;
    this._q("_leadSub").textContent =
      files === 0
        ? "No Claude Code settings files were found on this machine."
        : `Checked ${reviewed} grant${reviewed === 1 ? "" : "s"} across ${files} settings file${files === 1 ? "" : "s"}`;

    const toss = countTier(items, "TOSS"),
      side = countTier(items, "SIDEYE"),
      vip = countTier(items, "VIP");
    fillBar(this._q("_lSumBar"), toss, side, vip, items.length || 1);
    fillLegend(this._q("_lLegend"), toss, side, vip);

    const fblock = this._q("_findingsBlock"),
      flist = this._q("_findingList");
    const reasonCounts = Object.fromEntries(
      REASON_ORDER.filter((r) => r !== "SAFE")
        .map((r) => [r, countReason(items, r)])
        .filter(([, n]) => n > 0),
    );
    const present = Object.keys(reasonCounts);
    if (!present.length) {
      fblock.classList.add("hidden");
    } else {
      fblock.classList.remove("hidden");
      flist.replaceChildren(
        ...present.map((r) => {
          const n = reasonCounts[r];
          const sev = r === "OVERBROAD" ? "orange" : "red";
          const ex = items.find((i) => i.reason === r);
          const example = ex
            ? ex.display.length > 64
              ? ex.display.slice(0, 63) + "…"
              : ex.display
            : "";
          const go = () =>
            emit(this, "gg-navigate", { scope: "all", filter: { kind: "reason", value: r } });
          const frow = h(
            "div",
            { class: "frow", "data-reason": r, role: "button", tabindex: "0", onclick: go },
            [
              h("span", { class: "ficon " + sev }, [svgEl(REASON_SVG[r])]),
              h("div", { class: "fbody" }, [
                h("div", { class: "fname", text: REASONS[r] }),
                h("div", { class: "fex", text: example }),
              ]),
              h("span", { class: "fcount " + sev, text: String(n) }),
              h("span", { class: "fchev", "aria-hidden": "true" }, [CHEVRON_EL.cloneNode(true)]),
            ],
          );
          frow.onkeydown = (e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              go();
            }
          };
          return frow;
        }),
      );
    }

    const ns = this._q("_nextSteps");
    if (files === 0) {
      ns.replaceChildren(
        h("p", {
          class: "ov-note",
          text: "Grants appear here once you've used Claude Code and clicked “always allow”.",
        }),
      );
    } else if (flagged > 0) {
      const label = this._session.removed > 0 ? "Review the rest →" : "Review flagged →";
      ns.replaceChildren(
        h("button", {
          class: "btn primary",
          text: label,
          onclick: () => emit(this, "gg-scope-change", "all"),
        }),
        h("p", {
          class: "ov-note",
          text: "You'll see every flagged permission and can deselect anything before removing. Nothing is removed until you confirm.",
        }),
      );
    } else {
      ns.replaceChildren(
        h("button", {
          class: "btn",
          text: "Browse all permissions →",
          onclick: () => emit(this, "gg-scope-change", "all"),
        }),
      );
    }

    if (files > 0 && (this._session.removed > 0 || this._session.found === 0)) this._renderShare();
    else this._q("_share").replaceChildren();
  }

  // Share is a reward: shown only once the user has cleaned up, or was clean from the first scan.
  _renderShare() {
    const praise =
      this._session.removed > 0
        ? "Nice work keeping your permissions scoped and safe. As a small token of appreciation, we'd be grateful if you shared it:"
        : "Your permissions are already scoped and safe. If GrantGuard was useful, a share would mean a lot:";
    const xBtn = h(
      "button",
      {
        class: "btn share-btn",
        "aria-label": "Share on X",
        onclick: () => emit(this, "gg-share-open", "x"),
      },
      [svgEl(X_SVG), "Share on X"],
    );
    const liBtn = h(
      "button",
      {
        class: "btn share-btn",
        "aria-label": "Share on LinkedIn",
        onclick: () => emit(this, "gg-share-open", "linkedin"),
      },
      [svgEl(LINKEDIN_SVG), "Share on LinkedIn"],
    );
    const kids = [
      h("p", { class: "share-praise", text: praise }),
      h("div", { class: "share-row" }, [xBtn, liBtn]),
    ];
    if (this._session.secretRemoved)
      kids.push(
        h("p", {
          class: "share-warn",
          text: "One removed rule held a live credential — rotate it; deleting the rule doesn't un-leak it.",
        }),
      );
    this._q("_share").replaceChildren(...kids);
  }
}
customElements.define("gg-overview", GgOverview);

// ── <gg-share-modal> ──────────────────────────────────────────────────────────
// Created dynamically and appended to <body>; removes itself on close.
class GgShareModal extends HTMLElement {
  connectedCallback() {
    const isX = this.platform === "x";
    const ta = h("textarea", { class: "modal-caption", rows: "5", spellcheck: "false" });
    ta.value = this.caption;
    const status = h("span", { class: "modal-status" });

    const onKey = (e) => {
      if (e.key === "Escape") close();
    };
    const close = () => {
      this.remove();
      document.removeEventListener("keydown", onKey);
    };

    const copyBtn = h("button", {
      class: "btn",
      text: "Copy caption",
      onclick: async () => {
        try {
          await navigator.clipboard.writeText(ta.value);
          status.textContent = "Copied ✓";
        } catch {
          ta.focus();
          ta.select();
          status.textContent = "Press ⌘/Ctrl-C to copy";
        }
      },
    });
    const goBtn = h("button", {
      class: "btn primary",
      text: isX ? "Open X" : "Copy & open LinkedIn",
      onclick: async () => {
        if (isX) {
          window.open(
            `https://x.com/intent/post?text=${encodeURIComponent(ta.value)}&url=${encodeURIComponent(this.repoUrl)}`,
            "_blank",
            "noopener",
          );
        } else {
          try {
            await navigator.clipboard.writeText(ta.value);
          } catch {
            /* user can copy manually */
          }
          window.open(
            `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(this.repoUrl)}`,
            "_blank",
            "noopener",
          );
        }
        close();
      },
    });

    this.className = "modal-overlay";
    this.onclick = (e) => {
      if (e.target === this) close();
    };
    this.replaceChildren(
      h(
        "div",
        { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": "Preview your post" },
        [
          h("div", { class: "modal-head" }, [
            isX ? svgEl(X_SVG) : svgEl(LINKEDIN_SVG),
            h("h3", {
              class: "modal-title",
              text: isX ? "Preview your post on X" : "Preview your post on LinkedIn",
            }),
          ]),
          h("p", {
            class: "modal-note",
            text: isX
              ? "This text pre-fills the X composer — edit it here or there. The repo link is added automatically."
              : "LinkedIn can't pre-fill text, so we'll copy this caption for you to paste.",
          }),
          ta,
          h("div", { class: "modal-link" }, [
            "Shares ",
            h("code", { text: "github.com/VantaInc/grantguard" }),
          ]),
          h("div", { class: "modal-actions" }, [
            status,
            h("button", { class: "btn", text: "Cancel", onclick: close }),
            copyBtn,
            goBtn,
          ]),
        ],
      ),
    );
    document.addEventListener("keydown", onKey);
    ta.focus();
    ta.select();
  }
}
customElements.define("gg-share-modal", GgShareModal);

// ── <gg-list-pane> ────────────────────────────────────────────────────────────
class GgListPane extends HTMLElement {
  connectedCallback() {
    this.replaceChildren(
      h("div", { class: "toolbar" }, [
        h("div", { class: "tb-left" }, [
          h("span", { class: "h-title", id: "_hTitle" }),
          h("span", { class: "h-sub", id: "_hSub" }),
        ]),
        h("div", { class: "tb-right" }, [
          h(
            "button",
            { id: "_selectHarmful", class: "btn", onclick: () => this._onSelectHarmful() },
            ["Select flagged"],
          ),
          h("button", { id: "_clearBtn", class: "btn", onclick: () => this._onClear() }, ["Clear"]),
          h(
            "button",
            {
              id: "_applyBtn",
              class: "btn primary",
              onclick: () => this._onApply(),
              disabled: true,
            },
            ["Remove selected…"],
          ),
        ]),
      ]),
      h("div", { class: "summary" }, [
        h("div", { class: "sum-head" }, [
          h("span", { class: "sum-title", text: "Summary" }),
          h("span", { class: "sum-total", id: "_sumTotal" }),
        ]),
        h("div", { class: "sumbar", id: "_sumBar" }),
        h("div", { class: "legend", id: "_legend" }),
      ]),
      h("div", { class: "rows", id: "_rows" }),
      h("div", { class: "result hidden" }),
    );
  }

  update({ data, activeIdx: ai, filter: f, selected: sel }) {
    this._data = data;
    this._activeIdx = ai;
    this._filter = f;
    this._selected = sel;
    this._renderSummary();
    this._renderRows();
    this._updateApply();
  }

  _q(id) {
    return this.querySelector("#" + id);
  }

  _onSelectHarmful() {
    visibleItems(this._data, this._activeIdx, this._filter).forEach((it) => {
      if (it._src.editable && it.recommend_remove) this._selected.add(key(it._sidx, it.rule));
    });
    this._renderRows();
    this._updateApply();
  }
  _onClear() {
    scopeItems(this._data, this._activeIdx).forEach((it) =>
      this._selected.delete(key(it._sidx, it.rule)),
    );
    this._renderRows();
    this._updateApply();
  }
  _onApply() {
    emit(this, "gg-apply-request", null);
  }

  _renderSummary() {
    const { _data: data, _activeIdx: activeIdx, _filter: filter } = this;
    const visible = visibleItems(data, activeIdx, filter);
    const total = scopeItems(data, activeIdx).length || 1;
    const scopeLabel = activeIdx === "all" ? "all sources" : data.sources[activeIdx].label;
    this._q("_sumTotal").textContent =
      `${visible.length} rule${visible.length === 1 ? "" : "s"} · ${scopeLabel}`;

    const toss = countTier(visible, "TOSS"),
      side = countTier(visible, "SIDEYE"),
      vip = countTier(visible, "VIP");
    fillBar(this._q("_sumBar"), toss, side, vip, total);
    fillLegend(this._q("_legend"), toss, side, vip);
  }

  _renderRows() {
    const { _data: data, _activeIdx: activeIdx, _filter: filter, _selected: selected } = this;
    const items = visibleItems(data, activeIdx, filter);
    const title =
      filter.kind === "all"
        ? "All rules"
        : filter.kind === "tier"
          ? TIER_LABEL[filter.value]
          : REASONS[filter.value];
    this._q("_hTitle").textContent = title;
    this._q("_hSub").textContent = `${items.length} rule${items.length === 1 ? "" : "s"}`;

    const host = this._q("_rows");
    host.replaceChildren();
    for (const it of items) {
      const t = TIER[it.tier];
      const cb = h("input", {
        type: "checkbox",
        checked: selected.has(key(it._sidx, it.rule)),
        disabled: !it._src.editable,
      });
      cb.onchange = (e) => {
        const k = key(it._sidx, it.rule);
        if (e.target.checked) selected.add(k);
        else selected.delete(k);
        this._updateApply();
      };
      const why = h("span", { class: "why" }, [
        it.label,
        activeIdx === "all" ? h("span", { class: "src-tag", text: basename(it._src.path) }) : null,
      ]);
      const body = h("span", { class: "body" }, [h("code", { text: it.display }), why]);
      const badge = h("span", { class: "badge " + t.badge, text: t.label });
      host.appendChild(h("label", { class: "row" }, [cb, body, badge]));
    }
  }

  _updateApply() {
    const n = this._selected.size;
    this._q("_applyBtn").disabled = n === 0;
    this._q("_applyBtn").textContent = n ? `Remove ${n} selected…` : "Remove selected…";
    this._q("_selectHarmful").disabled = !visibleItems(
      this._data,
      this._activeIdx,
      this._filter,
    ).some((i) => i._src.editable && i.recommend_remove);
  }
}
customElements.define("gg-list-pane", GgListPane);

// ── App ────────────────────────────────────────────────────────────────────────
const SCAN_LINES = [
  "Scanning for settings files…",
  "Checking your home folder…",
  "Checking your projects…",
  "Classifying allow rules…",
  "Tallying results…",
];

// Reset to the recommended selection (every flagged rule in an editable source).
// Takes the state to mutate so callers stay inside a single setState pass.
function resetSelection(s) {
  s.selected.clear();
  s.data.sources.forEach((src, si) => {
    if (src.editable)
      src.items.forEach((it) => {
        if (it.recommend_remove) s.selected.add(key(si, it.rule));
      });
  });
}

function renderAll({ data, view, activeIdx, filter, selected, session }) {
  $("gg-nav").update({ data, view, activeIdx, filter });
  $("gg-scope").update({ data });

  const isOverview = view === "overview";
  $("gg-overview").classList.toggle("hidden", !isOverview);
  $("gg-list-pane").classList.toggle("hidden", isOverview);

  if (isOverview) {
    $("#path").textContent = "";
    $("gg-overview").update({ data, session });
  } else {
    $("#path").textContent =
      activeIdx === "all"
        ? `${data.sources.length} source${data.sources.length === 1 ? "" : "s"}`
        : data.sources[activeIdx].path;
    $("gg-list-pane").update({ data, activeIdx, filter, selected });
  }
}

function groupByFile() {
  const byFile = {};
  for (const k of state.selected) {
    const [sidx, rule] = parseKey(k);
    const src = state.data.sources[sidx];
    if (src && src.editable) (byFile[src.path] ||= []).push(rule);
  }
  return byFile;
}

async function applySelected() {
  const byFile = groupByFile();
  return Promise.all(
    Object.keys(byFile).map(async (f) => {
      const out = await fetch("/api/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-GrantGuard-Token": API_TOKEN },
        body: JSON.stringify({ file: f, remove: byFile[f] }),
      }).then((r) => r.json());
      return { file: f, ...out };
    }),
  );
}

// Fake progress bar: advances to 90% randomly while `work` runs, then snaps to 100%.
// Returns whatever the callback returned.
async function animateScan(work) {
  let p = 0,
    i = 0;
  const barEl = $("#bar");
  const scanlineEl = $("#scanline");
  const t = setInterval(() => {
    p = Math.min(p + Math.random() * 16, 90);
    barEl.style.width = p + "%";
    if (i < SCAN_LINES.length && Math.random() < 0.6) scanlineEl.textContent = SCAN_LINES[i++];
  }, 200);

  try {
    const result = await work();
    barEl.style.width = "100%";
    await new Promise((r) => setTimeout(r, 400));
    return result;
  } finally {
    clearInterval(t); // a rejected work() must not leave the bar animating forever
  }
}

async function run() {
  const data = await animateScan(fetchAudit);
  $("#scan").classList.add("hidden");
  $("#content").classList.remove("hidden");
  $("#platform").textContent = data.platform;
  $("#rerun").disabled = false;

  setState((s) => {
    s.data = data;
    resetSelection(s);
    s.session.found = s.session.found ?? allItems(data).filter((i) => i.recommend_remove).length;
    s.view = "overview";
  });
}

// ── Global event listeners (component → app) ──────────────────────────────────
document.addEventListener("gg-view-change", (e) => {
  setState({ view: e.detail, filter: { kind: "all", value: null } });
});

document.addEventListener("gg-scope-change", (e) => {
  setState({ view: "detail", activeIdx: e.detail, filter: { kind: "all", value: null } });
});

document.addEventListener("gg-filter-change", (e) => {
  setState({ view: "detail", filter: { kind: e.detail.kind, value: e.detail.value } });
});

document.addEventListener("gg-navigate", (e) => {
  setState({ view: "detail", activeIdx: e.detail.scope, filter: e.detail.filter });
});

document.addEventListener("gg-scope-apply", async (e) => {
  const { mode, targets } = e.detail;
  const scopeEl = $("gg-scope");
  scopeEl.showError("");
  $("#rerun").disabled = true; // a concurrent re-run would race the scope change
  $("#content").classList.add("hidden");
  $("#scan").classList.remove("hidden");
  $("#bar").style.width = "0%";
  let body = null;
  let errorMessage = "";
  try {
    const r = await animateScan(() =>
      fetch("/api/scope", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-GrantGuard-Token": API_TOKEN },
        body: JSON.stringify({ mode, targets }),
      }),
    );
    body = await r.json().catch((parseError) => {
      console.error("Failed to parse scope response from server", parseError);
      return null;
    });
    // Only a well-formed report may reach setState — a truncated 200 must not.
    if (!r.ok || !body || !Array.isArray(body.sources)) {
      errorMessage = body?.error ?? "Could not change the scan scope.";
      body = null;
    }
  } catch (err) {
    console.error("Scope change request failed", err);
    errorMessage = "Could not reach the GrantGuard server — is it still running?";
  } finally {
    $("#scan").classList.add("hidden");
    $("#content").classList.remove("hidden");
    $("#rerun").disabled = false;
  }
  // body and errorMessage are mutually exclusive: every error path above nulls
  // body and sets errorMessage, so a truthy body never carries a stale message.
  if (!body) {
    scopeEl.showError(errorMessage);
    return;
  }
  // A new scope is a fresh audit: reset the selection, view, and share narrative.
  setState((s) => {
    s.data = body;
    resetSelection(s);
    s.view = "overview";
    s.activeIdx = "all";
    s.filter = { kind: "all", value: null };
    s.session = { found: flaggedTotal(body), removed: 0, secretRemoved: false };
  });
});

document.addEventListener("gg-share-open", (e) => {
  const modal = document.createElement("gg-share-modal");
  modal.platform = e.detail;
  modal.caption = shareCaption(state.session);
  modal.repoUrl = REPO_URL;
  document.body.appendChild(modal);
});

document.addEventListener("gg-apply-request", async () => {
  if (!state.selected.size) return;
  const byFile = groupByFile();
  const files = Object.keys(byFile);
  const total = files.reduce((n, f) => n + byFile[f].length, 0);
  if (!total) return;
  if (
    !confirm(
      `Remove ${total} rule(s) across ${files.length} file(s)?\n\nThis updates the settings file in place. You can re-approve any permission later in Claude Code.`,
    )
  )
    return;
  const res = await applySelected();
  const data = await fetchAudit();
  // Re-scan so counts reflect the removal, then land on the Summary to celebrate.
  setState((s) => {
    s.data = data;
    resetSelection(s);
    s.view = "overview";
    s.session.removed += res.reduce((n, r) => n + (r.removed || 0), 0);
    s.session.secretRemoved = s.session.secretRemoved || res.some((r) => r.had_secret);
  });
  window.scrollTo(0, 0);
});

$("#rerun").onclick = async () => {
  $("#rerun").disabled = true;
  const data = await fetchAudit();
  $("#rerun").disabled = false;
  setState((s) => {
    s.data = data;
    resetSelection(s);
    if (s.view === "detail" && s.activeIdx !== "all" && s.activeIdx >= data.sources.length)
      s.activeIdx = "all";
  });
};

run();
