// SENSIENT.js
// 森鑫算法（双射实现，固定种子 ht1416）
// Exports: sensientEncrypt(input8, seed='ht1416'), sensientDecrypt(code6, seed='ht1416')

(function(global){
  const chars = 'ABCDEFGHJKLMNPRSTUVWXYZ23456789'; // 32 chars
  const CHARLEN = chars.length;
  const SEED_DEFAULT = 'ht1416';
  const ROUNDS = 4;

  // domain size: 100 * 26 * 26 * 10000 = 676000000
  const N = 100 * 26 * 26 * 10000;

  // encode input "DDLLDDDD" -> integer in [0, N)
  function encodeInput(s){
    // s assumed uppercase, validated by UI
    const dd = parseInt(s.slice(0,2), 10);        // 0..99
    const L1 = s.charCodeAt(2) - 65;              // 0..25
    const L2 = s.charCodeAt(3) - 65;              // 0..25
    const last4 = parseInt(s.slice(4,8), 10);     // 0..9999
    return ((dd * 26 + L1) * 26 + L2) * 10000 + last4;
  }

  // decode integer in [0,N) -> "DDLLDDDD"
  function decodeInput(n){
    const last4 = n % 10000;
    n = Math.floor(n / 10000);
    const L2 = n % 26; n = Math.floor(n / 26);
    const L1 = n % 26; n = Math.floor(n / 26);
    const dd = n % 100;
    return pad2(dd) + String.fromCharCode(65 + L1) + String.fromCharCode(65 + L2) + pad4(last4);
  }

  function pad2(x){ return (x<10 ? '0' : '') + String(x); }
  function pad4(x){ let s = String(x); while(s.length<4) s='0'+s; return s; }

  // deterministic 32-bit seed from string
  function stringToSeed(str){
    let h = 0;
    for(let i=0;i<str.length;i++){
      h = (h * 31 + str.charCodeAt(i)) & 0xFFFFFFFF;
    }
    return h >>> 0;
  }

  // mulberry32 PRNG: returns function() => float [0,1)
  function mulberry32(a){
    return function(){
      a = (a + 0x6D2B79F5) & 0xFFFFFFFF;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1) & 0xFFFFFFFF;
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61) & 0xFFFFFFFF;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // Feistel round function F(R, roundIdx, seedKey)
  function F_func(R, roundIdx, seedKey){
    const s = seedKey + '-' + roundIdx + '-' + R;
    const sd = stringToSeed(s);
    const rng = mulberry32(sd);
    // produce a 16-bit value
    return Math.floor(rng() * 0x10000) & 0xFFFF;
  }

  // PRP on 32-bit domain (Feistel with 16-bit halves)
  function prp32(x, seedKey){
    let L = (x >>> 16) & 0xFFFF;
    let R = x & 0xFFFF;
    for(let r=0;r<ROUNDS;r++){
      const F = F_func(R, r, seedKey) & 0xFFFF;
      const newL = R;
      const newR = (L + F) & 0xFFFF;
      L = newL; R = newR;
    }
    // combine
    return ((L << 16) | R) >>> 0;
  }

  function prp32_inv(y, seedKey){
    let L = (y >>> 16) & 0xFFFF;
    let R = y & 0xFFFF;
    for(let r=ROUNDS-1; r>=0; r--){
      const R0 = L;
      const F = F_func(R0, r, seedKey) & 0xFFFF;
      const L0 = (R - F) & 0xFFFF;
      L = L0; R = R0;
    }
    return ((L << 16) | R) >>> 0;
  }

  // encode integer v (should be < N) into 6-char using charset (base 32)
  function numToCode(v){
    let tmp = v;
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

  // cycle-walking PRP mapping: input x in [0,N) -> produce y in [0,N)
  // We use prp32 as PRP over 32-bit space; we cycle-walk until result < N.
  function cycleWalkEncrypt(x, seedKey){
    // embed x as 32-bit integer (x < N < 2^32)
    let v = prp32(x >>> 0, seedKey);
    let attempts = 0;
    while(v >= N){
      v = prp32(v, seedKey);
      attempts++;
      if(attempts > 1000000) throw new Error('cycle-walk exceeded attempts');
    }
    return v;
  }

  function cycleWalkDecrypt(y, seedKey){
    // inverse: repeatedly apply inverse PRP until value < N and then iterate inverse until find original
    let v = y >>> 0;
    let attempts = 0;
    while(v >= N){
      v = prp32_inv(v, seedKey);
      attempts++;
      if(attempts > 1000000) throw new Error('inverse cycle-walk exceeded attempts');
    }
    // Now v < N is the permuted value; original x is found by applying inverse PRP repeatedly until we reach a value < N that maps forward to y.
    // We can iterate inverse PRP until we find candidate x such that cycleWalkEncrypt(x) == y (guaranteed found within cycle).
    let candidate = v;
    attempts = 0;
    while(true){
      // check forward mapping
      if(cycleWalkEncrypt(candidate, seedKey) === y) return candidate;
      candidate = prp32_inv(candidate, seedKey);
      attempts++;
      if(attempts > 1000000) throw new Error('reconstruction exceeded attempts');
    }
  }

  // Public: sensientEncrypt(input8, seed='ht1416') -> 6-char code (no HT-)
  function sensientEncrypt(input8, seedKey){
    seedKey = seedKey || SEED_DEFAULT;
    // input8 validated by UI; uppercase expected
    const x = encodeInput(input8);
    const y = cycleWalkEncrypt(x, seedKey);
    return numToCode(y);
  }

  // Public: sensientDecrypt(code6, seed='ht1416') -> original input "DDLLDDDD"
  function sensientDecrypt(code6, seedKey){
    seedKey = seedKey || SEED_DEFAULT;
    const y = codeToNum(code6);
    // y should be < 2^32, but may be >= N; we need to find preimage via inverse cycle-walk:
    const x = cycleWalkDecrypt(y, seedKey);
    return decodeInput(x);
  }

  // export to global
  global.sensientEncrypt = sensientEncrypt;
  global.sensientDecrypt = sensientDecrypt;
  // compatibility object
  global.SensientAlgorithm = {
    encrypt: function(leftRight, seed){ return sensientEncrypt(leftRight, seed); },
    decrypt: function(code, seed){ return sensientDecrypt(code, seed); }
  };

})(typeof window !== 'undefined' ? window : (typeof global !== 'undefined' ? global : this));
