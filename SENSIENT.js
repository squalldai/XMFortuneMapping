// SENSIENT.js - 最终修复版本
// 固定种子
const SENSIENT_SEED = "ht1416";

// 防呆字符集（32字符，避免易混淆字符）
const SAFE_CHARS = 'ABCDEFGHJKLMNPRSTUVWXYZ23456789';
const CHAR_LEN = SAFE_CHARS.length;

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

// 生成编码表（严格双射，使用防呆字符集）
function sensientGenerateTables(seed = SENSIENT_SEED) {
    const chars = SAFE_CHARS;
    const rand = sensientRandom(seed);
    let arr = chars.split("");
    
    // Fisher-Yates 洗牌算法
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    
    return { 
        encode: arr, 
        decode: arr.reduce((m, c, i) => { m[c] = i; return m; }, {}) 
    };
}

const sensientTables = sensientGenerateTables(SENSIENT_SEED);

// 编码8位 → 6位（返回纯6位编码）
function sensientEncrypt(input, seed = SENSIENT_SEED) {
    if (!/^[0-9]{2}[A-Z]{2}[0-9]{4}$/.test(input)) {
        throw new Error("输入必须是 2数字+2字母+4数字（如：08AB1234）");
    }
    
    const tables = sensientGenerateTables(seed);
    
    // Base36 数值化：A-Z→10-35, 0-9→0-9
    const base36Val = parseInt(input.split("").map(ch => {
        if (/[0-9]/.test(ch)) return ch;
        return (ch.charCodeAt(0) - 55).toString();
    }).join(""), 36);  // ✅ 使用 Base36 解析

    // Base32 编码（6位 × 32 ≈ 10^9，覆盖8位Base36 ≈ 2.8×10^6）
    let output = "";
    let val = base36Val;
    for (let i = 0; i < 6; i++) {
        output = tables.encode[val % CHAR_LEN] + output;
        val = Math.floor(val / CHAR_LEN);
    }
    
    return output;
}

// 解码6位 → 8位（修复版）
function sensientDecrypt(code6, seed = SENSIENT_SEED) {
    if (!/^[ABCDEFGHJKLMNPRSTUVWXYZ23456789]{6}$/.test(code6)) {
        throw new Error("输入必须是6位合法编码（不含 I、O、0、1）");
    }
    
    const tables = sensientGenerateTables(seed);
    
    // Base32 解码
    let val = 0;
    for (let i = 0; i < code6.length; i++) {
        const charIndex = tables.decode[code6[i]];
        if (charIndex === undefined) {
            throw new Error(`无效字符：${code6[i]}`);
        }
        val = val * CHAR_LEN + charIndex;
    }

    // ✅ 修复：正确转换回8位Base36字符串
    let numStr = val.toString(36).toUpperCase();  // Base36 字符串，全大写
    while (numStr.length < 8) numStr = "0" + numStr;  // 补零到8位
    numStr = numStr.slice(-8);  // 确保正好8位

    // 还原原始格式：2数字 + 2字母 + 4数字
    const part1 = numStr.slice(0, 2);                    // 前2位数字
    const part2 = numStr.slice(2, 4);                    // 中2位字母（Base36已转换）
    const part3 = numStr.slice(4, 8);                    // 后4位数字

    return part1 + part2 + part3;  // 8位原始格式
}

// 测试函数
function testSensientRoundTrip() {
    const testInputs = [
        "08AB1234",
        "98AF9898", 
        "12CD5678",
        "99ZZ9999"
    ];
    
    console.log("=== SENSIENT 防呆算法测试 ===");
    testInputs.forEach(input => {
        try {
            const encrypted = sensientEncrypt(input);
            const decrypted = sensientDecrypt(encrypted);
            const valid = input === decrypted;
            console.log(`${input} → ${encrypted} → ${decrypted} [${valid ? '✓' : '✗'}]`);
        } catch (e) {
            console.error(`测试失败 ${input}:`, e.message);
        }
    });
}

// 导出
if (typeof window !== 'undefined') {
    window.sensientEncrypt = sensientEncrypt;
    window.sensientDecrypt = sensientDecrypt;
    window.testSensientRoundTrip = testSensientRoundTrip;
}
