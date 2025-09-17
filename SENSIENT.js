// SENSIENT.js (修正版)
// 森鑫算法 — 直接在 domain 上做 Feistel（可逆）
// 固定种子：'ht1416'
// Exports:
//   sensientEncrypt(input8, seed='ht1416') -> 6-char code (no "HT-")
//   sensientDecrypt(code6, seed='ht1416') -> original "DDLLDDDD"

(function(global){
  const chars = 'ABCDEFGHJKLMNPRSTUVWXYZ23456789'; // 32 chars
  const CHARLEN = chars.length;
  const SEED_DEFAULT = 'ht1416';

  // domain decomposition:
  // leftRange = 100 * 26 * 26 = 67600
  // rightRange = 10000
  const LEFT_RANGE = 100 * 26 * 26; // 67600
  const RIGHT_RANGE = 10000;
  const N = LEFT_RANGE * RIGHT_RANGE; // 676000000

  // helpers
  function pad2(x){ return (x < 10 ? '0' : '') + String(x); }
  function pad4(x){ let s=String(x); while(s.length<4) s='0'+s; return s; }

  // encode "DDLLDDDD" -> integer in [0, N)
  function encodeInput(str){
    // assume uppercase & validated
    const dd = parseInt(str.slice(0,2),10);         // 0..99
    const L1 = str.charCodeAt(2) - 65;              // 0..25
    const L2 = str.charCodeAt(3) - 65;              // 0..25
    const last4 = parseInt(str.slice(4,8),10);      // 0..9999
    const left = (dd * 26 + L1) * 26 + L2;         // 0..67599 (LEFT_RANGE-1)
    return left * RIGHT_RANGE + last4;
  }

  function decodeInput(n){
    const last4 = n % RIGHT_RANGE;
    n = Math.floor(n / RIGHT_RANGE);
    const L2 = n % 26; n = Math.floor(n / 26);
    const L1 = n % 26; n = Math.floor(n / 26);
    const dd = n % 100;
    return pad2(dd) + String.fromCharCode(65 + L1) + String.fromCharCode(65 + L2) + pad4(last4);
  }

  // deterministic 32-bit seed from string
  function stringToSeed(str){
    let h = 0;
    for(let i=0;i<str.length;i++){
      h = (h * 31 + str.charCodeAt(i)) & 0xFFFFFFFF;
    }
    return h >>> 0;
  }

  // mulberry32 PRNG (returns float in [0,1))
  function mulberry32(a){
    return function(){
      a = (a + 0x6D2B79F5) & 0xFFFFFFFF;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1) & 0xFFFFFFFF;
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61) & 0xFFFFFFFF;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // round function F(R, roundIdx, seedKey) -> integer in [0, LEFT_RANGE)
  function F_func(R, roundIdx, seedKey){
    const s = seedKey + '-' + roundIdx + '-' + R;
    const sd = stringToSeed(s);
    const rng = mulberry32(sd);
    return Math.floor(rng() * LEFT_RANGE);
  }

  // Feistel on domain (left in [0,LEFT_RANGE), right in [0,RIGHT_RANGE))
  const ROUNDS = 6; // 可调整（6轮够充分扩散）

  function feistel_encrypt_domain(combined, seedKey){
    let L = Math.floor(combined / RIGHT_RANGE); // 0..LEFT_RANGE-1
    let R = combined % RIGHT_RANGE;             // 0..RIGHT_RANGE-1
    for(let r=0; r<ROUNDS; r++){
      const F = F_func(R, r, seedKey); // 0..LEFT_RANGE-1
      // newL = R (but R is in smaller domain); to keep domain consistent we do:
      // we perform: newL = R (mod LEFT_RANGE) but R < RIGHT_RANGE possibly > LEFT_RANGE; to ensure reversibility we keep mapping:
      // We'll use: newL = R % LEFT_RANGE  (but RIGHT_RANGE = 10000 < LEFT_RANGE=67600, so R < LEFT_RANGE - OK)
      const newL = R; // safe because RIGHT_RANGE (10000) < LEFT_RANGE (67600)
      const newR = (L + F) % LEFT_RANGE;
      L = newL; R = newR;
    }
    return L * RIGHT_RANGE + R;
  }

  function feistel_decrypt_domain(permuted, seedKey){
    let L = Math.floor(permuted / RIGHT_RANGE);
    let R = permuted % RIGHT_RANGE;
    for(let r=ROUNDS-1; r>=0; r--){
      const R0 = L;
      const F = F_func(R0, r, seedKey);
      const L0 = (R - F + LEFT_RANGE) % LEFT_RANGE;
      L = L0; R = R0;
    }
    return L * RIGHT_RANGE + R;
  }

  // number < N -> 6-char code (base 32)
  function numToCode(v){
    let tmp = v >>> 0;
    let out = '';
    for(let i=0;i<6;i++){
      out += chars[tmp % CHARLEN];
      tmp = Math.floor(tmp / CHARLEN);
    }
    return out;
  }

  function codeToNum(code){
    let num = 0;
    for(let i=code.length-1;i>=0;i--){
      num = num * CHARLEN + chars.indexOf(code[i]);
    }
    return num;
  }

  // Public API
  function sensientEncrypt(input8, seedKey){
    seedKey = seedKey || SEED_DEFAULT;
    // Input must be validated by UI: 2 digits + 2 letters + 4 digits
    input8 = input8.toUpperCase();
    const x = encodeInput(input8); // 0..N-1
    const perm = feistel_encrypt_domain(x, seedKey); // still in 0..N-1
    return numToCode(perm);
  }

  function sensientDecrypt(code6, seedKey){
    seedKey = seedKey || SEED_DEFAULT;
    const v = codeToNum(code6);
    // v may be >= N because code space is 32^6 (~1.07e9) > N (6.76e8)
    // But when we encoded we used perm < N; so codeToNum should return that same number < N.
    // If someone supplies an out-of-domain code (>=N), we should fail/handle.
    if(v >= N){
      // this code wasn't produced by sensientEncrypt (out of domain)
      throw new Error('无效编码（不在 sensient 输出域内）');
    }
    const orig = feistel_decrypt_domain(v, seedKey);
    return decodeInput(orig);
  }

  // Export to global
  global.sensientEncrypt = sensientEncrypt;
  global.sensientDecrypt = sensientDecrypt;
  global.SensientAlgorithm = {
    encrypt: function(s, seed){ return sensientEncrypt(s, seed); },
    decrypt: function(code, seed){ return sensientDecrypt(code, seed); }
  };

})(typeof window !== 'undefined' ? window : (typeof global !== 'undefined' ? global : this));
