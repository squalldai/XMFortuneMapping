// ADMALGORITHEM.js
// 里程碑1算法（Feistel + 加法模）
// 保持和 v3.0 模拟验证一致的实现，严格可逆，种子固定：ht1416

const ADMAlgorithm = (function(){
  const chars = 'ABCDEFGHJKLMNPRSTUVWXYZ23456789';
  const CHARLEN = chars.length;
  const seedKey = 'ht1416';
  const ROUNDS = 4;
  const BASE = 10000; // each half-block range 0..9999

  // string -> 32-bit seed (deterministic)
  function stringToSeed(str){
    let hash = 0;
    for(let i=0;i<str.length;i++){
      hash = (hash * 31 + str.charCodeAt(i)) & 0xFFFFFFFF;
    }
    return hash >>> 0;
  }

  // mulberry32 PRNG
  function mulberry32(a){
    return function(){
      a = (a + 0x6D2B79F5) & 0xFFFFFFFF;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1) & 0xFFFFFFFF;
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61) & 0xFFFFFFFF;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // round function F(R, roundIdx)
  function F_func(R, roundIdx){
    const s = seedKey + '-' + roundIdx + '-' + R;
    const sd = stringToSeed(s);
    const rng = mulberry32(sd);
    return Math.floor(rng() * BASE); // 0..BASE-1
  }

  // Feistel encrypt (addition-based, invertible)
  function feistel_encrypt(combined){
    let L = Math.floor(combined / BASE);
    let R = combined % BASE;
    for(let r=0;r<ROUNDS;r++){
      const F = F_func(R, r);
      const newL = R;
      const newR = (L + F) % BASE;
      L = newL; R = newR;
    }
    return L * BASE + R;
  }

  // Feistel decrypt (inverse)
  function feistel_decrypt(permuted){
    let L = Math.floor(permuted / BASE);
    let R = permuted % BASE;
    for(let r=ROUNDS-1; r>=0; r--){
      const R0 = L;
      const F = F_func(R0, r);
      const L0 = (R - F + BASE) % BASE;
      L = L0; R = R0;
    }
    return L * BASE + R;
  }

  // number -> 6-char code (least-significant first like earlier implementations)
  function numToCode(num){
    let tmp = num;
    let out = '';
    for(let i=0;i<6;i++){
      out += chars[tmp % CHARLEN];
      tmp = Math.floor(tmp / CHARLEN);
    }
    return out;
  }

  function codeToNum(code){
    let num = 0;
    for(let i=code.length - 1; i>=0; i--){
      num = num * CHARLEN + chars.indexOf(code[i]);
    }
    return num;
  }

  // public API: encrypt(leftFull, right4) -> returns 6-char code (no HT- prefix)
  function encrypt(leftFull, right4){
    const left4 = leftFull.slice(-4);
    const combined = parseInt(left4 + right4, 10);
    const perm = feistel_encrypt(combined);
    return numToCode(perm);
  }

  // public API: decrypt(code) -> returns {left: '7688xxxx', right: 'yyyy'}
  function decrypt(code){
    const perm = codeToNum(code);
    const original = feistel_decrypt(perm);
    const combinedStr = String(original).padStart(8, '0');
    const left4 = combinedStr.slice(0,4);
    const right4 = combinedStr.slice(4,8);
    return { left: '7688' + left4, right: right4 };
  }

  return {
    encrypt,
    decrypt
  };
})();
