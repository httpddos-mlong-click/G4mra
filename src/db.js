const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '../data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const USERS_FILE  = path.join(DATA_DIR, 'users.json');
const SOLVES_FILE = path.join(DATA_DIR, 'solves.json');
const HINTS_FILE  = path.join(DATA_DIR, 'hints.json');
const COUNTS_FILE = path.join(DATA_DIR, 'solve_counts.json');

function read(file, def) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return def; }
}
// Atomic write: write to .tmp then rename — prevents partial reads
function write(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
}

// In-memory mutex per operation type to prevent race conditions
const _locks = {};
async function withLock(key, fn) {
  while (_locks[key]) await new Promise(r => setTimeout(r, 5));
  _locks[key] = true;
  try { return await fn(); }
  finally { delete _locks[key]; }
}

const db = {
  getUsers:  () => read(USERS_FILE,  []),
  getSolves: () => read(SOLVES_FILE, []),
  getHints:  () => read(HINTS_FILE,  []),
  getCounts: () => read(COUNTS_FILE, {}),
  saveUsers:  d => write(USERS_FILE,  d),
  saveSolves: d => write(SOLVES_FILE, d),
  saveHints:  d => write(HINTS_FILE,  d),
  saveCounts: d => write(COUNTS_FILE, d),

  getUserById:       id => db.getUsers().find(u => u.id === id),
  // Case-insensitive username lookup — prevents Admin/admin collision
  getUserByUsername: u  => db.getUsers().find(x => x.username.toLowerCase() === u.toLowerCase()),
  getUserByEmail:    e  => db.getUsers().find(x => x.email.toLowerCase() === e.toLowerCase()),

  async createUser(username, email, password_hash) {
    return withLock('users', () => {
      const users = db.getUsers();
      // Double-check uniqueness inside lock
      if (users.find(u => u.username.toLowerCase() === username.toLowerCase()))
        throw new Error('USERNAME_TAKEN');
      if (users.find(u => u.email.toLowerCase() === email.toLowerCase()))
        throw new Error('EMAIL_TAKEN');
      const id = users.length ? Math.max(...users.map(u => u.id)) + 1 : 1;
      const colors = ['#00d4ff','#00ff88','#ff6b6b','#ffd700','#b44dff','#ff8c00','#2ec4b6'];
      const avatar_color = colors[Math.floor(Math.random() * colors.length)];
      const user = { id, username, email, password_hash, avatar_color, points: 0, created_at: new Date().toISOString() };
      users.push(user);
      db.saveUsers(users);
      return user;
    });
  },

  async updateUserPoints(id, delta) {
    return withLock('users', () => {
      const users = db.getUsers();
      const u = users.find(x => x.id === id);
      if (u) {
        u.points = Math.max(0, (u.points || 0) + delta); // floor at 0, no negative points
        db.saveUsers(users);
      }
      return u;
    });
  },

  getUserSolves: uid => db.getSolves().filter(s => s.user_id === uid),
  getUserHints:  uid => db.getHints().filter(h => h.user_id === uid),
  hasSolved: (uid, cid) => db.getSolves().some(s => s.user_id === uid && s.challenge_id === cid),
  hasHint:   (uid, cid) => db.getHints().some(h => h.user_id === uid && h.challenge_id === cid),

  async addSolve(uid, cid, pts) {
    return withLock('solves_' + uid, async () => {
      // Re-check inside lock to prevent double-solve race
      if (db.hasSolved(uid, cid)) return { duplicate: true };
      const solves = db.getSolves();
      solves.push({ user_id: uid, challenge_id: cid, points_awarded: pts, solved_at: new Date().toISOString() });
      db.saveSolves(solves);
      await db.updateUserPoints(uid, pts);
      const counts = db.getCounts();
      counts[cid] = (counts[cid] || 0) + 1;
      db.saveCounts(counts);
      const ch = CHALLENGES.find(c => c.id === cid);
      if (ch) ch.solve_count = counts[cid];
      return { duplicate: false };
    });
  },

  async addHint(uid, cid, cost) {
    return withLock('hints_' + uid, async () => {
      // Re-check inside lock to prevent double-unlock race
      if (db.hasHint(uid, cid)) return { duplicate: true };
      // Re-verify points inside lock
      if (cost > 0) {
        const user = db.getUserById(uid);
        if (!user || user.points < cost) return { insufficient: true };
      }
      const hints = db.getHints();
      hints.push({ user_id: uid, challenge_id: cid, unlocked_at: new Date().toISOString() });
      db.saveHints(hints);
      if (cost > 0) await db.updateUserPoints(uid, -cost);
      return { duplicate: false };
    });
  },
};

function dynamicPoints(base_points, solve_count) {
  const floor = Math.max(50, Math.round(base_points * 0.2));
  const k = 0.08;
  return Math.max(floor, Math.round(base_points - (base_points - floor) * (1 - Math.exp(-k * (solve_count || 0)))));
}

const CHALLENGES = [
  // ── WEB ──────────────────────────────────────────────────────────────────
  { id:1,  slug:'web-flask-session',       category:'WEB',
    title:'Flask Session',
    description:'An internal employee portal with multiple access tiers. Something about the way sessions are handled feels... off.',
    difficulty:'Easy',   base_points:100,
    flag:'QA{yamate_senpai_access_granted_2026}',
    hint:'The secret key lives somewhere in the environment. Check what the log file reveals about accessible paths.',
    hint_cost:50, solve_count:0, author:'G4ram' },

  { id:2,  slug:'web-babel-stage1',        category:'WEB',
    title:'The Babel Protocol — Stage 1',
    description:'A mysterious translation service that speaks in protocols long forgotten. Stage 1 of 2.',
    difficulty:'Hard',   base_points:300,
    flag:'QA{w4sm_r3v3rs1ng_xxe_00b_ssrf_ch41n}',
    hint:'Reverse the .wat file to discover the valid root tag. Then craft an XXE OOB payload pointing to internal-service:8888.',
    hint_cost:200, solve_count:0, author:'G4ram' },

  { id:3,  slug:'web-babel-stage2',        category:'WEB',
    title:'The Babel Protocol — Stage 2',
    description:'The protocol speaks again, but this time it remembers who you are. Or does it? Stage 2 of 2.',
    difficulty:'Insane', base_points:500,
    flag:'QA{sst1_f0rg3d_s3ss10n_rc3_ch41n_byp4ss}',
    hint:'SQLi at /api/search. SSTI bypass: use |map(attribute=var) instead of |attr. Split dunders: "__cl"~"ass__".',
    hint_cost:350, solve_count:0, author:'G4ram' },

  { id:4,  slug:'web-the-race',            category:'WEB',
    title:'The Race',
    description:'Three doors. One way through. The clock is ticking and the window is narrow. Can you finish the race?',
    difficulty:'Insane', base_points:500,
    flag:'QA{smuggl1ng_r4c3_c0nd1t10n_ful1_syst3m_t4k30v3r}',
    hint:'Stage 1: XXE OOB+SSRF. Stage 2: SQLi → session forge → SSTI. Stage 3: race window 3ms, XOR key = MD5(seed+token)[:5].',
    hint_cost:450, solve_count:0, author:'G4ram' },

  { id:5,  slug:'web-binary-convergence',  category:'WEB',
    title:'The Binary-Web Convergence',
    description:'Where binaries meet the web, secrets live in the walls. A vault that trusts a little too much.',
    difficulty:'Hard',   base_points:350,
    flag:'QA{p4th_tr4v3rs4l_un1c0d3_n0rm4l1z4t10n}',
    hint:'XXE leaks /app/.env → APP_SECRET_KEY + VAULT_UUIDs. Hash the UUID: SHA256(APP_SECRET_KEY+uuid). Path traversal: /vault/sealed/flag.txt via Unicode normalization bypass.',
    hint_cost:250, solve_count:0, author:'G4ram' },

  // ── PWN ──────────────────────────────────────────────────────────────────
  { id:6,  slug:'pwn-overvaulted',         category:'PWN',
    title:'OverVaulted',
    description:"A vault with numbers that don't quite add up. Maybe that's the point.",
    difficulty:'Medium', base_points:200,
    flag:'QA{0v3r_v4ult3d_h34p_0verfl0w}',
    hint:'OP_SYSCALL 1 leaks the reveal_flag address and GLOBAL_COOKIE. Integer overflow: v->capacity + new_cap wraps to 0.',
    hint_cost:100, solve_count:0, author:'G4ram' },

  { id:7,  slug:'pwn-obsidian-vm',         category:'PWN',
    title:'Obsidian VM',
    description:'A custom runtime that compiles fast and trusts blindly. Speed kills.',
    difficulty:'Hard',   base_points:350,
    flag:'QA{0bs1d14n_jit_pwn_func_tabl3}',
    hint:'JIT buffer is 256 bytes. func_table[0] sits at offset +256. Fill the buffer with opcodes then write the target address.',
    hint_cost:200, solve_count:0, author:'G4ram' },

  { id:8,  slug:'pwn-vaultvm2',            category:'PWN',
    title:'VaultVM 2',
    description:'The vault evolved. The compiler remained naive. History repeats.',
    difficulty:'Hard',   base_points:350,
    flag:'QA{v4ult_vm2_jit_c0rrupt10n}',
    hint:'flag_printer @ 0x402c69. func_table[0] = jit_page+256. Use opcode 0x7e to STORE arbitrary values into the JIT page.',
    hint_cost:200, solve_count:0, author:'G4ram' },

  { id:9,  slug:'pwn-ksmbd',               category:'PWN',
    title:'KsmbDead',
    description:"Deep in the kernel, a driver handles file sharing. Sharing is caring — unless it's your privileges.",
    difficulty:'Insane', base_points:500,
    flag:'QA{k3rn3l_ksmb_d34d_r00t_esc4p3}',
    hint:'Load ksmbd.ko in Ghidra. The race lies in session reference counting — two threads can free the same object.',
    hint_cost:450, solve_count:0, author:'G4ram' },

  { id:10, slug:'pwn-ksmbd-hell',          category:'PWN',
    title:'KSMBD HELL',
    description:'The driver hardened itself. More locks, more walls, more rules. Rules can be broken.',
    difficulty:'Insane', base_points:500,
    flag:'QA{ksmbd_h3ll_byp4ss_4ll_m1t1g4t10ns}',
    hint:'Seccomp whitelist: read/write/exit only. Leak the canary first via an info-leak gadget before corrupting the stack.',
    hint_cost:450, solve_count:0, author:'G4ram' },

  // ── REV ──────────────────────────────────────────────────────────────────
  { id:11, slug:'rev-vietnamese',          category:'REV',
    title:'Vietnamese Identity',
    description:'A guardian that checks your identity before letting you through. Do you know who you really are?',
    difficulty:'Easy',   base_points:100,
    flag:'QA{be-qa-la-nguoi-viet-nam}',
    hint:'Read the bundled .c source. Trace the per-byte transforms and invert them one by one.',
    hint_cost:50, solve_count:0, author:'G4ram' },

  { id:12, slug:'rev-custom-hulk',         category:'REV',
    title:'Custom Hulk',
    description:'Something big, green, and layered in protection. Peel it back.',
    difficulty:'Hard',   base_points:350,
    flag:'QA{YEAHH_da_ra_flag_roi}',
    hint:'Layer 1 inverse: ROL2→SUB 0x5B→XOR(i*0x37)→MUL(inv 0x1D)→ROR3→XOR 0xA5. TEA key: DEADBEEF CAFEBABE 13371337 FEEDC0DE.',
    hint_cost:200, solve_count:0, author:'G4ram' },

  { id:13, slug:'rev-the-abyss',           category:'REV',
    title:'The Abyss',
    description:'You stare into the VM. The VM stares back. One of you is lying.',
    difficulty:'Insane', base_points:500,
    flag:'QA{4byss_vm_r3v_ch4ll3ng3}',
    hint:'Transform pipeline: XOR 0x5A → ADD i*7 → XOR 0xC3. Patch the debug check in bytecode or compute the inverse directly.',
    hint_cost:350, solve_count:0, author:'G4ram' },

  // ── CRYPTO ───────────────────────────────────────────────────────────────
  { id:14, slug:'crypto-spectral',         category:'CRYPTO',
    title:'Spectral',
    description:"An oracle that answers questions — but only up to a point. The answer you need lies just beyond its reach.",
    difficulty:'Hard',   base_points:350,
    flag:'QA{sp3ctr4l_k3y_r3c0v3ry}',
    hint:'Oracle returns up to 2000 bytes per request. Reconstruct the LFSR internal state, then extrapolate forward to offset 131072.',
    hint_cost:200, solve_count:0, author:'G4ram' },

  { id:15, slug:'crypto-aegis',            category:'CRYPTO',
    title:'Aegis',
    description:'A shield forged from mathematics. Elegant, ancient, and hiding a fatal flaw.',
    difficulty:'Hard',   base_points:350,
    flag:'QA{4eg1s_p0hl1g_h3llm4n_dlp}',
    hint:'Factor p-1 into small primes. Solve DLP in each subgroup with BSGS then combine via CRT. Max 100 exchanges per session.',
    hint_cost:200, solve_count:0, author:'G4ram' },

  { id:16, slug:'crypto-meridian',         category:'CRYPTO',
    title:'Meridian',
    description:'A lattice in the fog. Ask enough questions and the fog begins to clear.',
    difficulty:'Insane', base_points:500,
    flag:'QA{m3r1d14n_lw3_k3y_r3c0v3ry}',
    hint:'For each secret bit: send the unit vector, average LWE responses over many queries, threshold at q/2. HW=20 means exactly 20 bits are 1.',
    hint_cost:450, solve_count:0, author:'G4ram' },

  { id:17, slug:'crypto-triple-veil',      category:'CRYPTO',
    title:'Triple Veil',
    description:'Three curtains, one secret. The key was never in one place to begin with.',
    difficulty:'Insane', base_points:500,
    flag:'QA{tr1pl3_v31l_m4st3r_k3y}',
    hint:'Part 1: EXIF Comment of hint_image.png. Part 2: base64-decode body of pubkey.pem. Part 3: integrity field in config.json.',
    hint_cost:350, solve_count:0, author:'G4ram' },

  // ── FORENSICS ────────────────────────────────────────────────────────────
  { id:18, slug:'for-echoing-void',        category:'FORENSICS',
    title:'The Echoing Void',
    description:'A ghost in the network, whispering through channels no one monitors. Most of the noise is noise. Most.',
    difficulty:'Insane', base_points:500,
    flag:'QA{dns_c0v3rt_ch4nn3l_dg4_3xf1l}',
    hint:'Filter DNS queries with QNAME entropy > 4.0. XOR key for each chunk = TTL bytes of the corresponding DNS response.',
    hint_cost:450, solve_count:0, author:'G4ram' },

  { id:19, slug:'for-rootkit',             category:'FORENSICS',
    title:'Rootkit Extraction',
    description:'A module that loads in the dark and never announces itself. The flag is in there, sleeping.',
    difficulty:'Insane', base_points:500,
    flag:'QA{r00tk1t_k3rn3l_k3y_d3r1v3d}',
    hint:'Look up sys_read in System.map — this is the key base. XOR with the CPUID constant embedded in the .ko, then decrypt .rodata.',
    hint_cost:450, solve_count:0, author:'G4ram' },

  { id:20, slug:'for-digital-trail',       category:'FORENSICS',
    title:'Digital Trail',
    description:'Everyone leaves traces. Five layers of obfuscation, one trail of breadcrumbs.',
    difficulty:'Hard',   base_points:350,
    flag:'QA{m3m0ry_t3lls_4ll_s3cr3ts_fr0m_sl4ck_t0_h34p}',
    hint:'Stage 4: find process "qa_svchost" PID 3141 in memory.dmp. Flag is XOR-encoded at HEAP magic offset 0x100000; key = first 4 bytes of that heap chunk.',
    hint_cost:250, solve_count:0, author:'G4ram' },

  // ── MISC ─────────────────────────────────────────────────────────────────
  { id:21, slug:'misc-pulse',              category:'MISC',
    title:'The Pulse',
    description:'A video that beats like a heart. Listen carefully.',
    difficulty:'Medium', base_points:200,
    flag:'QA{B1T_BY_B1T}',
    hint:'Convert frames to YCrCb, compute mean(Y), diff adjacent frames, threshold at ±8 → ON/OFF. RLE: 2f HIGH = dot, 6f HIGH = dash.',
    hint_cost:100, solve_count:0, author:'G4ram' },

  { id:22, slug:'misc-hexagonal',          category:'MISC',
    title:'Hexagonal Veil',
    description:'Something was slipped into this file when no one was looking.',
    difficulty:'Medium', base_points:200,
    flag:'QA{boot2root_hi_1_4m_Quynh4nh}',
    hint:'Hunt for bytes 51 41 43 54 46 00 00 01. Next 2 bytes = payload length. XOR key = SHA256(flag_bytes)[:8].',
    hint_cost:100, solve_count:0, author:'G4ram' },

  { id:23, slug:'misc-hidden',             category:'MISC',
    title:'Hidden in Plain Sight',
    description:"The image looks ordinary. It isn't.",
    difficulty:'Medium', base_points:200,
    flag:'QA{h1dd3n_1n_pl41n_s1ght_lsb}',
    hint:'PIL/Pillow: extract LSBs from R channel → 4-byte length → 16-byte AES key → CBC-decrypt the remainder.',
    hint_cost:100, solve_count:0, author:'G4ram' },

  { id:24, slug:'misc-anime-girls',        category:'MISC',
    title:'AnimeGirlsParadox',
    description:'A paradox wrapped in motion. Not everything that moves is what it seems.',
    difficulty:'Medium', base_points:200,
    flag:'QA{m0t10n_s0ul_fr4gm3nt3d}',
    hint:'Analyze inter-frame motion vectors in the video. DCT coefficients in the chrominance channel carry the encoded flag fragments.',
    hint_cost:100, solve_count:0, author:'G4ram' },

  { id:25, slug:'misc-mahiru',             category:'MISC',
    title:'Mahiru',
    description:'Time is the message. Every frame tells you something if you measure carefully enough.',
    difficulty:'Hard',   base_points:350,
    flag:'QA{s31_n4l_fr4m3_jitt3r_m4st3r}',
    hint:'Extract PTS (presentation timestamps) from each frame. Compute delta between expected and actual PTS. Map deviations: small=0, large=1. Group into bytes.',
    hint_cost:200, solve_count:0, author:'G4ram' },
];

module.exports = { db, dynamicPoints, CHALLENGES };

// Boot recovery: restore solve_counts from disk
(function bootRecover() {
  try {
    const counts = db.getCounts();
    for (const ch of CHALLENGES) {
      if (counts[ch.id] !== undefined) ch.solve_count = counts[ch.id];
    }
    console.log('[boot] solve_counts restored:', JSON.stringify(counts));
  } catch(e) {
    console.warn('[boot] could not restore solve_counts:', e.message);
  }
})();
