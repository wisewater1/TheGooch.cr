require "kemal"
require "json"
require "../demo/scenario"

module TheGooch::Web
  BLOCK_COLORS = {
    "genesis"        => "#6b7280",
    "election"       => "#3b82f6",
    "tally"          => "#10b981",
    "legitimacy"     => "#8b5cf6",
    "deliberation"   => "#f59e0b",
    "minority"       => "#ef4444",
    "fork"           => "#f97316",
    "reconciliation" => "#06b6d4",
    "ratification"   => "#84cc16",
    "expiry"         => "#dc2626",
  }

  struct BlockView
    include JSON::Serializable
    getter index : Int32
    getter hash : String
    getter kind : String
    getter branch : String
    getter parents : Array(String)
    getter color : String
    getter summary : String

    def initialize(b : TheGooch::Block)
      @index = b.index
      @hash = b.hash[0, 10]
      @kind = b.body_kind
      @branch = b.branch_id
      @parents = b.prev_hashes.map { |h| h[0, 10] }
      @color = BLOCK_COLORS.fetch(b.body_kind, "#9ca3af")
      @summary = summarize(b)
    end

    private def summarize(b : TheGooch::Block) : String
      case b.body_kind
      when "genesis"
        "genesis"
      when "election"
        body = TheGooch::BlockBody::Election.from_json(b.body_json)
        "#{body.votes_json.size} votes"
      when "tally"
        body = TheGooch::BlockBody::Tally.from_json(b.body_json)
        "winner: #{body.winner} (margin #{body.raw_margin.round(3)})"
      when "legitimacy"
        body = TheGooch::BlockBody::Legitimacy.from_json(b.body_json)
        "trust mean=#{body.mean.round(3)}"
      when "deliberation"
        body = TheGooch::BlockBody::Deliberation.from_json(b.body_json)
        "HHI=#{body.report.hhi.round(3)} @#{body.report.dominant_region}"
      when "fork"
        body = TheGooch::BlockBody::Fork.from_json(b.body_json)
        body.criterion
      when "reconciliation"
        body = TheGooch::BlockBody::Reconciliation.from_json(b.body_json)
        body.decision
      when "ratification"
        "ratified"
      when "expiry"
        body = TheGooch::BlockBody::Expiry.from_json(b.body_json)
        "weight=#{body.decayed_weight.round(4)}"
      else
        ""
      end
    rescue
      ""
    end
  end

  struct TallyView
    include JSON::Serializable
    getter winner : String
    getter raw_margin : Float64
    getter per_candidate_raw : Hash(String, Int32)
    getter per_candidate_weighted : Hash(String, Float64)
    getter intensity_gap : Float64
    getter trust_mean : Float64
    getter trust_variance : Float64

    def initialize(@winner, @raw_margin, @per_candidate_raw, @per_candidate_weighted,
                   @intensity_gap, @trust_mean, @trust_variance)
    end
  end

  struct StateView
    include JSON::Serializable
    getter blocks : Array(BlockView)
    getter branches : Array(String)
    getter tally : TallyView?
    getter feature_blocks : Hash(String, Array(Int32))

    def initialize(@blocks, @branches, @tally, @feature_blocks)
    end
  end

  def self.build_state(result : TheGooch::Demo::Result) : StateView
    bc = result.blockchain
    blocks = bc.chain.blocks.values.sort_by(&.index).map { |b| BlockView.new(b) }
    branches = bc.chain.branches

    tally = nil
    bc.chain.each do |b|
      next unless b.body_kind == "tally"
      body = TheGooch::BlockBody::Tally.from_json(b.body_json)
      leg_mean = 0.0
      leg_var = 0.0
      bc.chain.each do |lb|
        next unless lb.body_kind == "legitimacy"
        lbody = TheGooch::BlockBody::Legitimacy.from_json(lb.body_json)
        leg_mean = lbody.mean
        leg_var = lbody.variance
      end
      tally = TallyView.new(body.winner, body.raw_margin, body.per_candidate_raw,
        body.per_candidate_weighted, body.intensity_gap, leg_mean, leg_var)
    end

    StateView.new(blocks, branches, tally, result.feature_blocks)
  end

  def self.run(port : Int32 = 3000,
               store : TheGooch::BlockStore::Base = TheGooch::BlockStore::Null.new)
    result = TheGooch::Demo.run(IO::Memory.new, 1.0e9, store)
    state = build_state(result)
    state_json = state.to_json

    get "/" do
      HTML_PAGE
    end

    get "/api/state" do |env|
      env.response.content_type = "application/json"
      state_json
    end

    Kemal.config.port = port
    Kemal.config.env = "production"
    puts "TheGooch visualizer → http://localhost:#{port}"
    ARGV.clear
    Kemal.run
  end

  HTML_PAGE = <<-HTML
  <!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8">
    <title>TheGooch — Chain Visualizer</title>
    <style>
      *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
      body { font-family: ui-monospace, 'Cascadia Code', monospace; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
      header { padding: 1.5rem 2rem; border-bottom: 1px solid #1e293b; display: flex; align-items: center; gap: 1rem; }
      header h1 { font-size: 1.25rem; font-weight: 700; color: #f8fafc; }
      header span { font-size: 0.75rem; color: #64748b; }
      .layout { display: grid; grid-template-columns: 1fr 320px; gap: 0; height: calc(100vh - 65px); }
      .main { overflow-y: auto; padding: 1.5rem 2rem; }
      .sidebar { border-left: 1px solid #1e293b; overflow-y: auto; padding: 1.5rem; }
      h2 { font-size: 0.7rem; letter-spacing: 0.1em; text-transform: uppercase; color: #475569; margin-bottom: 1rem; }

      /* DAG */
      #dag { width: 100%; overflow-x: auto; margin-bottom: 2rem; background: #0f172a; border-radius: 8px; border: 1px solid #1e293b; }
      svg text { font-family: ui-monospace, monospace; font-size: 11px; fill: #e2e8f0; }

      /* Block list */
      .block-list { display: flex; flex-direction: column; gap: 0.5rem; }
      .block { display: flex; align-items: flex-start; gap: 0.75rem; padding: 0.6rem 0.75rem; border-radius: 6px; background: #1e293b; border: 1px solid #334155; cursor: default; }
      .block:hover { border-color: #475569; }
      .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.65rem; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; color: #fff; flex-shrink: 0; }
      .block-meta { display: flex; flex-direction: column; gap: 0.25rem; min-width: 0; }
      .block-title { font-size: 0.8rem; color: #f1f5f9; }
      .block-sub { font-size: 0.7rem; color: #64748b; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

      /* Tally */
      .stat { margin-bottom: 1rem; }
      .stat label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.08em; color: #64748b; display: block; margin-bottom: 0.25rem; }
      .stat value { font-size: 1.1rem; font-weight: 700; color: #f8fafc; }
      .bar-wrap { margin-top: 0.5rem; }
      .bar-label { font-size: 0.7rem; color: #94a3b8; margin-bottom: 0.25rem; display: flex; justify-content: space-between; }
      .bar-bg { background: #1e293b; border-radius: 4px; height: 8px; overflow: hidden; margin-bottom: 0.5rem; }
      .bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }

      /* Features */
      .feature-tag { display: inline-block; font-size: 0.65rem; padding: 0.2rem 0.5rem; border-radius: 3px; background: #1e293b; border: 1px solid #334155; color: #94a3b8; margin: 0.15rem; }
      .feature-tag.active { background: #1d4ed8; border-color: #3b82f6; color: #bfdbfe; }

      /* Branches */
      .branch-pill { display: inline-block; font-size: 0.65rem; padding: 0.15rem 0.5rem; border-radius: 100px; background: #0f172a; border: 1px solid #334155; color: #94a3b8; margin: 0.15rem; }
    </style>
  </head>
  <body>
    <header>
      <h1>TheGooch</h1>
      <span>Research-grade blockchain governance demo</span>
    </header>
    <div class="layout">
      <div class="main">
        <h2>Chain DAG</h2>
        <div id="dag"><svg id="dag-svg"></svg></div>
        <h2>Blocks</h2>
        <div class="block-list" id="block-list"></div>
      </div>
      <div class="sidebar">
        <h2>Tally</h2>
        <div id="tally-section"></div>
        <br>
        <h2>Branches</h2>
        <div id="branches"></div>
        <br>
        <h2>Features Fired</h2>
        <div id="features"></div>
      </div>
    </div>

    <script>
    const COLORS = #{BLOCK_COLORS.to_json};

    async function load() {
      const r = await fetch('/api/state');
      const s = await r.json();
      renderBlocks(s.blocks);
      renderDAG(s.blocks);
      renderTally(s.tally, s.blocks);
      renderBranches(s.branches);
      renderFeatures(s.feature_blocks);
    }

    function renderBlocks(blocks) {
      const el = document.getElementById('block-list');
      el.innerHTML = blocks.map(b => `
        <div class="block">
          <span class="badge" style="background:${COLORS[b.kind]||'#9ca3af'}">${b.kind}</span>
          <div class="block-meta">
            <div class="block-title">#${b.index} &nbsp; <span style="color:#475569">${b.hash}</span> &nbsp; <span style="color:#334155;font-size:0.65rem">[${b.branch}]</span></div>
            <div class="block-sub">${b.summary || '—'}</div>
          </div>
        </div>`).join('');
    }

    function renderDAG(blocks) {
      const BRANCH_COLORS = {'main':'#3b82f6','branch-A':'#10b981','branch-B':'#f97316'};
      const branchSet = [...new Set(blocks.map(b => b.branch))];
      const branchRow = {};
      branchSet.forEach((br, i) => branchRow[br] = i);
      const ROW_H = 90, COL_W = 140, PAD_X = 40, PAD_Y = 50;
      const rows = branchSet.length;
      const cols = blocks.length;
      const W = PAD_X * 2 + COL_W * cols;
      const H = PAD_Y * 2 + ROW_H * rows;

      const hashPos = {};
      blocks.forEach((b, i) => {
        const row = branchRow[b.branch] ?? 0;
        hashPos[b.hash] = { x: PAD_X + i * COL_W + 55, y: PAD_Y + row * ROW_H + 20 };
      });

      const svg = document.getElementById('dag-svg');
      svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
      svg.setAttribute('width', W);
      svg.setAttribute('height', H);

      let html = '';
      // Draw edges
      blocks.forEach(b => {
        const to = hashPos[b.hash];
        if (!to) return;
        b.parents.forEach(ph => {
          const from = hashPos[ph];
          if (!from) return;
          html += `<line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" stroke="#334155" stroke-width="1.5" marker-end="url(#arrow)"/>`;
        });
      });

      // Arrowhead
      html = `<defs><marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L6,3 z" fill="#475569"/></marker></defs>` + html;

      // Draw nodes
      blocks.forEach(b => {
        const pos = hashPos[b.hash];
        if (!pos) return;
        const c = COLORS[b.kind] || '#9ca3af';
        html += `<rect x="${pos.x - 50}" y="${pos.y - 16}" width="100" height="32" rx="6" fill="${c}" opacity="0.2" stroke="${c}" stroke-width="1.5"/>`;
        html += `<text x="${pos.x}" y="${pos.y - 2}" text-anchor="middle" font-weight="600" fill="${c}">${b.kind}</text>`;
        html += `<text x="${pos.x}" y="${pos.y + 12}" text-anchor="middle" fill="#64748b">#${b.index} ${b.hash.slice(0,6)}</text>`;
      });

      svg.innerHTML = html;
    }

    function renderTally(tally, blocks) {
      const el = document.getElementById('tally-section');
      if (!tally) { el.innerHTML = '<p style="color:#475569;font-size:0.75rem">No tally yet.</p>'; return; }
      const cands = Object.keys(tally.per_candidate_raw);
      const total = cands.reduce((s,c) => s + tally.per_candidate_raw[c], 0);
      const bars = cands.map(c => {
        const raw = tally.per_candidate_raw[c];
        const pct = total ? (raw/total*100).toFixed(1) : 0;
        const col = c === tally.winner ? '#10b981' : '#ef4444';
        return `<div class="bar-label"><span>${c}</span><span>${raw} votes (${pct}%)</span></div>
          <div class="bar-bg"><div class="bar-fill" style="width:${pct}%;background:${col}"></div></div>`;
      }).join('');
      el.innerHTML = `
        <div class="stat"><label>Winner</label><value>${tally.winner}</value></div>
        <div class="bar-wrap">${bars}</div>
        <div class="stat" style="margin-top:0.75rem"><label>Raw margin</label><value>${tally.raw_margin.toFixed(3)}</value></div>
        <div class="stat"><label>Intensity gap</label><value>${tally.intensity_gap.toFixed(3)}</value></div>
        <div class="stat"><label>Trust score (meta-vote)</label><value>${tally.trust_mean.toFixed(3)} <span style="font-size:0.75rem;color:#64748b">± ${Math.sqrt(tally.trust_variance).toFixed(3)}</span></value></div>`;
    }

    function renderBranches(branches) {
      document.getElementById('branches').innerHTML =
        branches.map(b => `<span class="branch-pill">${b}</span>`).join('');
    }

    function renderFeatures(fb) {
      const ALL = ['emotional','posthumous','meta_vote','minority','forking','decay'];
      document.getElementById('features').innerHTML =
        ALL.map(f => {
          const active = fb[f] && fb[f].length > 0;
          return `<span class="feature-tag ${active?'active':''}">${f}${active?' ✓':''}</span>`;
        }).join('');
    }

    load();
    </script>
  </body>
  </html>
  HTML
end
