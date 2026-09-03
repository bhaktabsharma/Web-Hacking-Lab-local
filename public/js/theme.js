(function () {
  const KEY = "whl_theme_v1";
  function getMode() { return localStorage.getItem(KEY) || "dark"; }
  function effectiveOf(mode) {
    if (mode === "system") return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    return mode;
  }
  function apply(mode) { document.documentElement.setAttribute("data-theme", effectiveOf(mode)); }
  function renderToggle() {
    const mode = getMode();
    document.querySelectorAll("#appearanceToggle button").forEach((btn) => btn.classList.toggle("active", btn.dataset.mode === mode));
  }
  function setMode(mode) {
    localStorage.setItem(KEY, mode);
    apply(mode);
    renderToggle();
  }
  document.querySelectorAll("#appearanceToggle button").forEach((btn) => btn.addEventListener("click", () => setMode(btn.dataset.mode)));
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => { if (getMode() === "system") apply("system"); });
  }
  apply(getMode());
  renderToggle();
})();
