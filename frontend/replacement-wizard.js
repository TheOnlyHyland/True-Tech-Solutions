const ROOMS = [
  { id: "living_room", name: "Living Room", status: "Connected", target: "12 C" },
  { id: "kitchen", name: "Kitchen", status: "Connected", target: "12 C" },
  { id: "downstairs_bathroom", name: "Downstairs Bathroom", status: "Connected", target: "12 C" },
  { id: "guest_room", name: "Guest Room", status: "Needs attention", target: "12 C" },
  { id: "our_bedroom", name: "Our Bedroom", status: "Connected", target: "12 C" },
  { id: "clarks_room", name: "Clark's Room", status: "Connected", target: "12 C" },
  { id: "upstairs_bathroom", name: "Upstairs Bathroom", status: "Connected", target: "12 C" },
];

const STEPS = ["Room", "Prepare", "Pair", "Verify", "Test"];

class TrueFamilyTrvReplacementDemo extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    const requestedStage = new URL(window.location.href).searchParams.get("stage");
    this.stage = [
      "room",
      "prepare",
      "pairing",
      "verify",
      "testing",
      "complete",
      "failed",
    ].includes(requestedStage)
      ? requestedStage
      : "room";
    this.roomId = "guest_room";
    this.seconds = 60;
    this.timer = undefined;
  }

  connectedCallback() {
    this.render();
  }

  disconnectedCallback() {
    this.stopTimer();
  }

  get room() {
    return ROOMS.find((room) => room.id === this.roomId) || ROOMS[0];
  }

  get stepIndex() {
    return {
      room: 0,
      prepare: 1,
      pairing: 2,
      verify: 3,
      testing: 4,
      complete: 5,
      failed: 2,
    }[this.stage];
  }

  render() {
    this.shadowRoot.innerHTML = `
      <style>${this.styles()}</style>
      <main class="canvas">
        <section class="shell" aria-label="Radiator valve replacement prototype">
          <header class="topbar">
            <div>
              <p class="eyebrow">True Family Care</p>
              <h1>Replace radiator valve</h1>
            </div>
            <span class="demo-pill">Demo mode</span>
          </header>
          <div class="body">
            ${this.renderProgress()}
            <section class="content" aria-live="polite">${this.renderStage()}</section>
          </div>
          <footer>
            <span>Nothing here is connected to live heating.</span>
            ${this.stage !== "room" && this.stage !== "complete" ? '<button class="text-button" data-action="cancel">Cancel</button>' : ""}
          </footer>
        </section>
      </main>
    `;
    this.bindEvents();
  }

  renderProgress() {
    const complete = this.stage === "complete";
    return `
      <nav class="progress" aria-label="Replacement progress">
        ${STEPS.map(
          (label, index) => `
            <div class="progress-step ${index < this.stepIndex || complete ? "done" : ""} ${index === this.stepIndex && !complete ? "active" : ""}">
              <span>${index < this.stepIndex || complete ? "OK" : index + 1}</span>
              <strong>${label}</strong>
            </div>`,
        ).join("")}
      </nav>
    `;
  }

  renderStage() {
    if (this.stage === "prepare") return this.renderPrepare();
    if (this.stage === "pairing") return this.renderPairing();
    if (this.stage === "verify") return this.renderVerify();
    if (this.stage === "testing") return this.renderTesting();
    if (this.stage === "complete") return this.renderComplete();
    if (this.stage === "failed") return this.renderFailed();
    return this.renderRoom();
  }

  renderRoom() {
    const options = ROOMS.map(
      (room) => `<option value="${room.id}" ${room.id === this.roomId ? "selected" : ""}>${room.name}</option>`,
    ).join("");
    return `
      <div class="copy">
        <p class="kicker">Start with the room</p>
        <h2>Which valve needs replacing?</h2>
        <p>The production design keeps the room and weekly plan in place. This prototype changes nothing.</p>
      </div>
      <label class="field">
        <span>Heating zone</span>
        <select data-room>${options}</select>
      </label>
      <article class="device-card">
        <span class="device-mark">TRV</span>
        <div>
          <strong>${this.room.name}</strong>
          <small>Moes BRT-100-TRV</small>
        </div>
        <div class="device-state warning">
          <span></span>${this.room.status}
        </div>
      </article>
      <div class="promise-row">
        <span>Schedule-safe design</span>
        <span>Stable room identity</span>
        <span>Rollback available</span>
      </div>
      <div class="actions"><button class="primary" data-action="prepare">Continue</button></div>
    `;
  }

  renderPrepare() {
    return `
      <div class="copy">
        <p class="kicker">${this.room.name}</p>
        <h2>Prepare the replacement valve</h2>
        <p>Keep the valve beside the radiator. Do not remove the old device from Home Assistant.</p>
      </div>
      <ol class="guide">
        <li><span>1</span><div><strong>Insert the batteries</strong><small>Use fresh batteries and leave the valve off the radiator for now.</small></div></li>
        <li><span>2</span><div><strong>Hold the pairing control</strong><small>Keep holding until the wireless symbol begins to flash.</small></div></li>
        <li><span>3</span><div><strong>Keep it close</strong><small>Stay near the nearest Zigbee router while True Family checks the valve.</small></div></li>
      </ol>
      <div class="notice"><strong>Security window</strong><span>Joining opens for 60 seconds and closes as soon as one valve is found.</span></div>
      <div class="actions split"><button class="secondary" data-action="room">Back</button><button class="primary" data-action="pair">Open pairing window</button></div>
    `;
  }

  renderPairing() {
    const circumference = 213.6;
    const offset = circumference * (1 - this.seconds / 60);
    return `
      <div class="pairing-layout">
        <div class="timer" aria-label="${this.seconds} seconds remaining">
          <svg viewBox="0 0 80 80" aria-hidden="true"><circle cx="40" cy="40" r="34"></circle><circle class="timer-progress" cx="40" cy="40" r="34" style="stroke-dashoffset:${offset}"></circle></svg>
          <strong>${this.seconds}</strong><small>seconds</small>
        </div>
        <div class="copy compact">
          <p class="kicker">Pairing is open</p>
          <h2>Looking for one new valve</h2>
          <p>Keep the wireless symbol flashing. The network will close automatically when the interview succeeds.</p>
        </div>
      </div>
      <div class="scan"><i></i><span>Listening for Zigbee2MQTT interview events</span></div>
      <div class="prototype-controls">
        <span>Prototype controls</span>
        <button class="secondary" data-action="found">Simulate approved valve</button>
        <button class="text-button danger" data-action="wrong">Simulate wrong device</button>
      </div>
    `;
  }

  renderVerify() {
    return `
      <div class="copy">
        <p class="kicker success-text">Pairing closed safely</p>
        <h2>Replacement valve found</h2>
        <p>Check the details before True Family changes the room binding.</p>
      </div>
      <article class="identity-card">
        <div class="identity-icon">TF</div>
        <dl>
          <div><dt>Room</dt><dd>${this.room.name}</dd></div>
          <div><dt>Manufacturer</dt><dd>Moes</dd></div>
          <div><dt>Model</dt><dd>BRT-100-TRV</dd></div>
          <div><dt>Device ID</dt><dd>...493F</dd></div>
        </dl>
        <span class="approved">Approved</span>
      </article>
      <div class="notice"><strong>The old binding is retained</strong><span>True Family can restore it if the connection test fails.</span></div>
      <div class="actions split"><button class="secondary" data-action="cancel">Cancel</button><button class="primary" data-action="test">Bind and test</button></div>
    `;
  }

  renderTesting() {
    return `
      <div class="testing">
        <div class="pulse"><span>12</span><small>target</small></div>
        <div class="copy compact">
          <p class="kicker">Final safety check</p>
          <h2>Waiting for the valve to answer</h2>
          <p>True Family sent the room's safe target and is waiting for the new valve to report 12 C back.</p>
        </div>
      </div>
      <div class="check-list">
        <span class="checked">Candidate identity checked</span>
        <span class="checked">Challenge target sent</span>
        <span class="checking">Restoring and confirming target</span>
      </div>
    `;
  }

  renderComplete() {
    return `
      <div class="complete-mark"><span>OK</span></div>
      <div class="copy centered">
        <p class="kicker success-text">Connectivity check complete</p>
        <h2>${this.room.name} valve is connected</h2>
        <p>The valve passed its connectivity check. Schedule migration is not enabled in this prototype.</p>
      </div>
      <div class="result-grid">
        <div><span>Connection</span><strong>Verified</strong></div>
        <div><span>Schedule</span><strong>Migration required</strong></div>
        <div><span>Next step</span><strong>Fit and calibrate</strong></div>
      </div>
      <div class="actions"><button class="primary" data-action="reset">Done</button></div>
    `;
  }

  renderFailed() {
    return `
      <div class="failed-mark">!</div>
      <div class="copy centered">
        <p class="kicker danger-text">Pairing stopped</p>
        <h2>This device is not an approved valve</h2>
        <p>Zigbee joining has been closed. Nothing in ${this.room.name} was changed.</p>
      </div>
      <div class="notice danger-notice"><strong>Safe outcome</strong><span>The old room binding and every schedule remain untouched.</span></div>
      <div class="actions split"><button class="secondary" data-action="cancel">Cancel</button><button class="primary" data-action="pair">Try again</button></div>
    `;
  }

  bindEvents() {
    this.shadowRoot.querySelector("[data-room]")?.addEventListener("change", (event) => {
      this.roomId = event.target.value;
      this.render();
    });
    this.shadowRoot.querySelectorAll("[data-action]").forEach((button) => {
      button.addEventListener("click", () => this.handleAction(button.dataset.action));
    });
  }

  handleAction(action) {
    if (action === "prepare") this.stage = "prepare";
    if (action === "room" || action === "cancel" || action === "reset") this.stage = "room";
    if (action === "pair") {
      this.stage = "pairing";
      this.seconds = 60;
      this.startTimer();
    }
    if (action === "found") {
      this.stopTimer();
      this.stage = "verify";
    }
    if (action === "wrong") {
      this.stopTimer();
      this.stage = "failed";
    }
    if (action === "test") {
      this.stage = "testing";
      this.render();
      window.setTimeout(() => {
        if (this.stage === "testing") {
          this.stage = "complete";
          this.render();
        }
      }, 1800);
      return;
    }
    this.render();
  }

  startTimer() {
    this.stopTimer();
    this.timer = window.setInterval(() => {
      if (this.stage !== "pairing") return this.stopTimer();
      this.seconds -= 1;
      if (this.seconds <= 0) {
        this.stopTimer();
        this.stage = "failed";
      }
      this.render();
    }, 1000);
  }

  stopTimer() {
    if (this.timer !== undefined) window.clearInterval(this.timer);
    this.timer = undefined;
  }

  styles() {
    return `
      :host { display:block; min-height:100vh; color:#142b43; }
      * { box-sizing:border-box; }
      button, select { font:inherit; }
      button { cursor:pointer; }
      .canvas { min-height:100vh; display:grid; place-items:center; padding:clamp(14px,3vw,34px); background:
        radial-gradient(circle at 12% 12%, rgba(255,255,255,.94), transparent 34%),
        radial-gradient(circle at 88% 20%, rgba(124,207,250,.42), transparent 32%),
        linear-gradient(145deg,#eef7fc 0%,#dbeaf7 52%,#d4e0f2 100%); }
      .shell { width:min(980px,100%); height:min(720px,calc(100vh - 28px)); min-height:620px; display:grid; grid-template-rows:auto 1fr auto; overflow:hidden; border:1px solid rgba(255,255,255,.82); border-radius:32px; background:rgba(250,253,255,.7); box-shadow:0 28px 80px rgba(45,80,113,.2), inset 0 1px rgba(255,255,255,.92); backdrop-filter:blur(28px) saturate(130%); }
      .topbar { display:flex; align-items:center; justify-content:space-between; padding:26px 30px 20px; border-bottom:1px solid rgba(78,116,151,.1); }
      .eyebrow,.kicker { margin:0 0 5px; color:#2878a9; font-size:11px; font-weight:800; letter-spacing:.14em; text-transform:uppercase; }
      h1 { margin:0; font-size:clamp(22px,3vw,32px); letter-spacing:-.035em; }
      .demo-pill { padding:8px 12px; border:1px solid rgba(48,132,182,.25); border-radius:999px; color:#256e9a; background:rgba(206,238,255,.68); font-size:11px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; }
      .body { min-height:0; display:grid; grid-template-columns:172px 1fr; }
      .progress { padding:24px 18px; border-right:1px solid rgba(78,116,151,.1); background:rgba(225,240,250,.34); }
      .progress-step { display:grid; grid-template-columns:28px 1fr; align-items:center; gap:10px; min-height:58px; color:#7890a6; font-size:13px; }
      .progress-step span { width:28px; height:28px; display:grid; place-items:center; border:1px solid rgba(93,127,157,.22); border-radius:10px; background:rgba(255,255,255,.5); font-size:10px; font-weight:800; }
      .progress-step strong { font-weight:700; }
      .progress-step.active { color:#18334d; }
      .progress-step.active span { color:white; border-color:#35a4df; background:linear-gradient(145deg,#53b9ed,#248dca); box-shadow:0 7px 18px rgba(38,143,202,.3); }
      .progress-step.done { color:#2c769e; }
      .progress-step.done span { color:#24759d; border-color:#a5d7ed; background:#dff4fd; }
      .content { min-width:0; padding:clamp(24px,4vw,42px); display:flex; flex-direction:column; justify-content:center; overflow:hidden; }
      .copy { max-width:650px; }
      .copy.compact { max-width:520px; }
      .copy.centered { margin-inline:auto; text-align:center; }
      h2 { margin:0; font-size:clamp(26px,4vw,40px); line-height:1.02; letter-spacing:-.045em; }
      .copy p:last-child { margin:12px 0 0; color:#607990; font-size:15px; line-height:1.55; }
      .field { display:grid; gap:7px; margin-top:24px; color:#536d83; font-size:12px; font-weight:750; }
      select { width:100%; padding:14px 16px; color:#17344e; border:1px solid rgba(70,114,148,.18); border-radius:15px; outline:none; background:rgba(255,255,255,.72); font-weight:750; }
      select:focus { border-color:#42a5dc; box-shadow:0 0 0 3px rgba(66,165,220,.15); }
      .device-card,.identity-card { display:flex; align-items:center; gap:14px; margin-top:14px; padding:16px; border:1px solid rgba(91,128,158,.14); border-radius:20px; background:rgba(255,255,255,.62); box-shadow:0 12px 30px rgba(78,108,135,.08); }
      .device-mark,.identity-icon { width:48px; height:48px; display:grid; place-items:center; flex:0 0 auto; border-radius:15px; color:#217fae; background:linear-gradient(145deg,#e6f7ff,#c7eafa); font-size:11px; font-weight:900; letter-spacing:.05em; }
      .device-card strong,.device-card small { display:block; }
      .device-card small { margin-top:3px; color:#7a90a3; }
      .device-state { display:flex; align-items:center; gap:7px; margin-left:auto; font-size:12px; font-weight:800; }
      .device-state span { width:8px; height:8px; border-radius:50%; background:#e29d39; box-shadow:0 0 0 5px rgba(226,157,57,.13); }
      .promise-row { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin-top:13px; }
      .promise-row span { padding:10px; border-radius:12px; color:#52748a; background:rgba(225,243,251,.56); font-size:11px; font-weight:700; text-align:center; }
      .actions { display:flex; justify-content:flex-end; margin-top:22px; }
      .actions.split { justify-content:space-between; }
      .primary,.secondary { min-width:128px; padding:12px 18px; border-radius:14px; border:0; font-weight:800; }
      .primary { color:white; background:linear-gradient(145deg,#43b1e7,#278cc8); box-shadow:0 10px 24px rgba(38,143,202,.27); }
      .secondary { color:#285873; border:1px solid rgba(54,113,148,.18); background:rgba(255,255,255,.62); }
      .text-button { padding:5px; color:#4e748b; border:0; background:transparent; font-size:12px; font-weight:750; }
      .danger { color:#b05858; }
      .guide { display:grid; gap:10px; margin:20px 0 0; padding:0; list-style:none; }
      .guide li { display:flex; align-items:center; gap:12px; padding:12px 14px; border:1px solid rgba(91,128,158,.12); border-radius:16px; background:rgba(255,255,255,.55); }
      .guide li > span { width:29px; height:29px; display:grid; place-items:center; flex:0 0 auto; border-radius:10px; color:#267da8; background:#daf1fc; font-size:11px; font-weight:900; }
      .guide strong,.guide small { display:block; }
      .guide small { margin-top:3px; color:#6d8598; font-size:12px; line-height:1.35; }
      .notice { display:flex; gap:10px; margin-top:14px; padding:12px 14px; border-radius:14px; color:#4e7187; background:rgba(214,240,251,.56); font-size:12px; }
      .notice strong { color:#255e7e; white-space:nowrap; }
      .pairing-layout,.testing { display:flex; align-items:center; justify-content:center; gap:28px; }
      .timer { position:relative; width:150px; height:150px; display:grid; place-items:center; flex:0 0 auto; }
      .timer svg { position:absolute; inset:0; width:100%; height:100%; transform:rotate(-90deg); }
      .timer circle { fill:none; stroke:rgba(59,124,159,.1); stroke-width:4; }
      .timer .timer-progress { stroke:#3aa9df; stroke-linecap:round; stroke-dasharray:213.6; transition:stroke-dashoffset .3s linear; }
      .timer strong { margin-top:-8px; font-size:44px; letter-spacing:-.06em; }
      .timer small { position:absolute; top:91px; color:#7390a3; }
      .scan { position:relative; display:flex; align-items:center; gap:12px; margin-top:26px; padding:15px 18px; overflow:hidden; border:1px solid rgba(71,135,169,.15); border-radius:15px; background:rgba(255,255,255,.54); color:#55778c; font-size:12px; font-weight:750; }
      .scan i { width:9px; height:9px; border-radius:50%; background:#38a7dc; box-shadow:0 0 0 0 rgba(56,167,220,.35); animation:beacon 1.5s infinite; }
      @keyframes beacon { 70% { box-shadow:0 0 0 10px rgba(56,167,220,0); } }
      .prototype-controls { display:flex; align-items:center; gap:12px; margin-top:18px; padding-top:15px; border-top:1px dashed rgba(76,119,150,.18); }
      .prototype-controls > span { margin-right:auto; color:#8396a7; font-size:10px; font-weight:850; letter-spacing:.1em; text-transform:uppercase; }
      .identity-card { position:relative; align-items:flex-start; }
      .identity-card dl { display:grid; grid-template-columns:repeat(2,minmax(120px,1fr)); gap:12px 28px; flex:1; margin:0; }
      .identity-card dl div { display:grid; gap:2px; }
      .identity-card dt { color:#7990a2; font-size:10px; font-weight:800; text-transform:uppercase; letter-spacing:.08em; }
      .identity-card dd { margin:0; font-size:13px; font-weight:800; }
      .approved { position:absolute; right:14px; top:14px; padding:6px 9px; border-radius:999px; color:#247a65; background:#dcf5eb; font-size:10px; font-weight:850; text-transform:uppercase; }
      .success-text { color:#277f6b; }
      .danger-text { color:#aa5656; }
      .pulse { width:132px; height:132px; display:grid; place-items:center; flex:0 0 auto; border-radius:42px; color:white; background:linear-gradient(145deg,#47b6e8,#2a88c3); box-shadow:0 20px 45px rgba(36,139,197,.3),0 0 0 13px rgba(72,181,232,.09); animation:float 2s ease-in-out infinite; }
      .pulse span { margin-top:15px; font-size:42px; font-weight:800; letter-spacing:-.07em; }
      .pulse small { position:absolute; margin-top:62px; opacity:.75; }
      @keyframes float { 50% { transform:translateY(-5px); } }
      .check-list { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin-top:28px; }
      .check-list span { padding:12px; border-radius:13px; background:rgba(255,255,255,.54); color:#5c7b8e; font-size:11px; font-weight:750; text-align:center; }
      .check-list .checked { color:#347c68; background:rgba(219,245,236,.6); }
      .check-list .checking { color:#287da8; background:rgba(215,240,251,.66); }
      .complete-mark,.failed-mark { width:78px; height:78px; display:grid; place-items:center; margin:0 auto 18px; border-radius:26px; font-size:18px; font-weight:900; }
      .complete-mark { color:#247961; background:linear-gradient(145deg,#e4f9f1,#ccefe2); box-shadow:0 14px 34px rgba(39,127,107,.15); }
      .failed-mark { color:#a34f4f; background:linear-gradient(145deg,#fff0ee,#f6d8d5); }
      .result-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:9px; margin-top:22px; }
      .result-grid div { display:grid; gap:3px; padding:13px; border:1px solid rgba(91,128,158,.12); border-radius:14px; background:rgba(255,255,255,.55); text-align:center; }
      .result-grid span { color:#7890a2; font-size:10px; font-weight:750; text-transform:uppercase; }
      .result-grid strong { font-size:13px; }
      .danger-notice { color:#895d5d; background:rgba(251,225,221,.58); }
      .danger-notice strong { color:#924d4d; }
      footer { display:flex; justify-content:space-between; align-items:center; min-height:48px; padding:10px 28px; border-top:1px solid rgba(78,116,151,.1); color:#8295a6; font-size:10px; }
      @media (max-width:700px) {
        .canvas { padding:0; }
        .shell { width:100%; height:100vh; min-height:0; border:0; border-radius:0; }
        .topbar { padding:18px 18px 14px; }
        .topbar h1 { font-size:22px; }
        .body { grid-template-columns:1fr; grid-template-rows:auto 1fr; }
        .progress { display:flex; justify-content:center; gap:7px; padding:10px 14px; border-right:0; border-bottom:1px solid rgba(78,116,151,.1); }
        .progress-step { display:block; min-height:auto; }
        .progress-step span { width:25px; height:25px; border-radius:9px; }
        .progress-step strong { display:none; }
        .content { padding:28px 18px 20px; justify-content:flex-start; }
        h2 { font-size:29px; }
        .copy p:last-child { font-size:13px; line-height:1.45; }
        .field { margin-top:16px; }
        .device-card { padding:13px; }
        .promise-row { grid-template-columns:1fr; gap:5px; }
        .promise-row span { padding:7px; }
        .guide { gap:7px; margin-top:14px; }
        .guide li { padding:9px 10px; }
        .notice { margin-top:10px; }
        .pairing-layout,.testing { flex-direction:column; gap:16px; text-align:center; }
        .timer { width:122px; height:122px; }
        .timer strong { font-size:38px; }
        .timer small { top:76px; }
        .prototype-controls { display:grid; grid-template-columns:1fr 1fr; }
        .prototype-controls > span { grid-column:1/-1; }
        .prototype-controls .secondary { min-width:0; }
        .identity-card { padding:13px; }
        .identity-card dl { grid-template-columns:1fr; gap:7px; }
        .identity-card dl div:nth-child(4) { display:none; }
        .check-list,.result-grid { grid-template-columns:1fr; gap:5px; }
        .check-list span,.result-grid div { padding:8px; }
        .pulse { width:105px; height:105px; border-radius:34px; }
        footer { padding:8px 16px; }
      }
      @media (prefers-reduced-motion:reduce) { *,*::before,*::after { animation:none !important; transition:none !important; } }
    `;
  }
}

customElements.define("true-family-trv-replacement-demo", TrueFamilyTrvReplacementDemo);
