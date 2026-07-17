const form = document.getElementById("analyze-form");
const input = document.getElementById("url-input");
const btn = document.getElementById("analyze-btn");
const loadingEl = document.getElementById("loading");
const resultEl = document.getElementById("result");
const errorEl = document.getElementById("error");

const RADIUS = 46;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function gaugeColor(pct) {
  if (pct >= 60) return "var(--red)";
  if (pct >= 30) return "var(--amber)";
  return "var(--green)";
}

function renderResult(data) {
  const pct = data.phishing_probability;
  const isPhishing = data.prediction === "phishing";
  const color = gaugeColor(pct);
  const offset = CIRCUMFERENCE - (pct / 100) * CIRCUMFERENCE;

  const signalsHtml = data.top_signals.length
    ? data.top_signals
        .map(
          (s) => `
        <div class="signal-row">
          <span class="signal-marker">&#9656;</span>
          <span class="signal-name">${s.name}</span>
          <span class="signal-desc">${s.explanation || "value: " + s.value}</span>
        </div>`
        )
        .join("")
    : `<div class="no-signals">No notable risk signals detected in this URL.</div>`;

  resultEl.innerHTML = `
    <div class="verdict-row">
      <div class="gauge-wrap">
        <svg width="108" height="108" viewBox="0 0 108 108">
          <circle class="gauge-track" cx="54" cy="54" r="${RADIUS}" fill="none" stroke-width="8"></circle>
          <circle class="gauge-fill" cx="54" cy="54" r="${RADIUS}" fill="none" stroke-width="8"
            stroke="${color}"
            stroke-dasharray="${CIRCUMFERENCE}"
            stroke-dashoffset="${CIRCUMFERENCE}"></circle>
        </svg>
        <div class="gauge-label">
          <span class="gauge-pct">${pct}%</span>
          <span class="gauge-caption">risk</span>
        </div>
      </div>
      <div class="verdict-text">
        <span class="verdict-badge ${isPhishing ? "badge-phishing" : "badge-legit"}">
          ${isPhishing ? "Likely Phishing" : "Likely Legitimate"}
        </span>
        <h2>${isPhishing ? "This URL looks suspicious" : "This URL looks safe"}</h2>
        <p>${data.url}</p>
      </div>
    </div>
    <div class="signals">
      <h3>Detected signals</h3>
      <div class="signal-log">${signalsHtml}</div>
    </div>
  `;

  resultEl.classList.remove("hidden");

  // animate the gauge fill on next frame
  requestAnimationFrame(() => {
    const fillCircle = resultEl.querySelector(".gauge-fill");
    requestAnimationFrame(() => {
      fillCircle.style.strokeDashoffset = String(offset);
    });
  });
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  errorEl.classList.add("hidden");
  resultEl.classList.add("hidden");
  loadingEl.classList.remove("hidden");
  btn.disabled = true;

  try {
    const res = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || "Something went wrong analyzing this URL.");
    }
    renderResult(data);
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove("hidden");
  } finally {
    loadingEl.classList.add("hidden");
    btn.disabled = false;
  }
});
