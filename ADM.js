// ADM.js
// 里程碑1算法对外接口：admEncrypt(leftFull, right4) / admDecrypt(code)
// 内部实现：Feistel (addition-based) + mulberry32-based round function
// 种子：ht1416，ROUNDS = 4，BASE = 10000

const ADM = (function(){
  const chars = 'ABCDEFGHJKLMNPRSTUVWXYZ23456789';
  const CHARLEN = chars.length;
  const seedKey = 'ht1416';
  const ROUNDS = 4;
  const BASE = 10000;

  function stringToSeed(str){
    let hash = 0;
    for(let i=0;i<str.length;i++){
      hash = (hash * 31 + str.charCodeAt(i)) & 0xFFFFFFFF;
    }
    return hash >>> 0;
  }

  function mulberry32(a){
    return function(){
      a = (a + 0x6D2B79F5) & 0xFFFFFFFF;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1) & 0xFFFFFFFF;
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61) & 0xFFFFFFFF;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function F_func(R, roundIdx){
    const s = seedKey + '-' + roundIdx + '-' + R;
    const sd = stringToSeed(s);
    const rng = mulberry32(sd);
    return Math.floor(rng() * BASE);
  }

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

  // 对外接口（保持与 index.html 期望一致的行为）
  function admEncrypt(leftFull, right4){
    // leftFull: e.g. "76880800"  (前四位7688固定)
    // right4: e.g. "1111"
    const left4 = leftFull.slice(-4);
    const combined = parseInt(left4 + right4, 10);
    const perm = feistel_encrypt(combined);
    return numToCode(perm); // 返回 6 字符（不带 "HT-" 前缀）
  }

  function admDecrypt(code){
    const perm = codeToNum(code);
    const original = feistel_decrypt(perm);
    const combinedStr = String(original).padStart(8, '0');
    const left4 = combinedStr.slice(0,4);
    const right4 = combinedStr.slice(4,8);
    return { left: '7688' + left4, right: right4 };
  }

  // 导出
  return {
    admEncrypt,
    admDecrypt
  };
})();

// 兼容旧引用（如果 index.html 之前引用 ADMAlgorithm.encrypt）
if(typeof window !== 'undefined'){
  window.ADMAlgorithm = {
    encrypt: function(leftFull, right4){ return ADM.admEncrypt(leftFull, right4); },
    decrypt: function(code){ return ADM.admDecrypt(code); }
  };
  // 也导出新命名
  window.admEncrypt = ADM.admEncrypt;
  window.admDecrypt = ADM.admDecrypt;
}
