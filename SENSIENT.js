// 固定种子
const SENSIENT_SEED = "ht1416";

// 生成伪随机数（确定性，基于种子）
function sensientRandom(seed) {
    let h = 0;
    for (let i = 0; i < seed.length; i++) {
        h = Math.imul(31, h) + seed.charCodeAt(i) | 0;
    }
    return function () {
        h ^= h << 13;
        h ^= h >> 17;
        h ^= h << 5;
        return (h >>> 0) / 4294967296;
    }
}

// 生成编码表（严格双射）
function sensientGenerateTables() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const rand = sensientRandom(SENSIENT_SEED);
    let arr = chars.split("");
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return { encode: arr, decode: arr.reduce((m, c, i) => { m[c] = i; return m; }, {}) };
}

const sensientTables = sensientGenerateTables();

// 编码8位 → 6位
function sensientEncrypt(input) {
    if (!/^[0-9]{2}[A-Z]{2}[0-9]{4}$/.test(input)) {
        return "输入必须是 2数字+2字母+4数字";
    }
    const base36Val = parseInt(input.split("").map(ch => {
        if (/[0-9]/.test(ch)) return ch;
        return (ch.charCodeAt(0) - 55).toString();
    }).join(""), 10);

    let output = "";
    let val = base36Val;
    for (let i = 0; i < 6; i++) {
        output = sensientTables.encode[val % 36] + output;
        val = Math.floor(val / 36);
    }
    return "HT-" + output;
}

// 解码6位 → 8位
function sensientDecrypt(input) {
    if (!/^HT-[A-Z0-9]{6}$/.test(input)) {
        return "输入必须是 HT- 开头 + 6位字母数字";
    }
    const code = input.slice(3);
    let val = 0;
    for (let i = 0; i < code.length; i++) {
        val = val * 36 + sensientTables.decode[code[i]];
    }

    let numStr = val.toString();
    while (numStr.length < 8) numStr = "0" + numStr;

    // 转换成原始格式（2数字+2字母+4数字）
    let part1 = numStr.slice(0, 2);
    let part2 = String.fromCharCode(parseInt(numStr.slice(2, 4)) + 55);
    let part3 = numStr.slice(4);

    return part1 + part2 + part3;
}
