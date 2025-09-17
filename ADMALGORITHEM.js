// ADMALGORITHEM.js
// 里程碑1算法 (核心逻辑)

// 使用固定种子，保证加解密可逆
function seededRandom(seed) {
  let x = Math.sin(seed) * 10000;
  return x - Math.floor(x);
}

function shuffleWithSeed(arr, seed) {
  let array = arr.slice();
  for (let i = array.length - 1; i > 0; i--) {
    let j = Math.floor(seededRandom(seed + i) * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

const ADMAlgorithm = {
  encrypt: function(left, right) {
    // 左 8位 + 右 4位
    const input = left + right;

    // 用左侧作为种子扰动
    const seed = parseInt(left.slice(-4)) || 1416;

    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const shuffled = shuffleWithSeed(chars.split(""), seed);

    let num = parseInt(right, 10);
    let base36 = "";
    while (num > 0) {
      base36 = shuffled[num % shuffled.length] + base36;
      num = Math.floor(num / shuffled.length);
    }
    base36 = base36.padStart(6, shuffled[0]);

    return "HT-" + base36;
  },

  decrypt: function(left, rightEncoded) {
    const seed = parseInt(left.slice(-4)) || 1416;
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const shuffled = shuffleWithSeed(chars.split(""), seed);

    let num = 0;
    for (let i = 0; i < rightEncoded.length; i++) {
      const val = shuffled.indexOf(rightEncoded[i]);
      num = num * shuffled.length + val;
    }

    const decodedRight = num.toString().padStart(4, "0");
    return left + decodedRight;
  }
};
