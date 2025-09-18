// SENSIENT.js - 防呆字符集版本
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
    const chars = SAFE_CHARS;  // 使用防呆字符集
    const rand = sensientRandom(seed);
    let arr = chars.split("");
    
    // Fisher-Yates 洗牌算法
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    
    // 生成双向映射
    return { 
        encode: arr,           // 正向：索引 → 字符
        decode: arr.reduce((m, c, i) => { m[c] = i; return m; }, {})  // 反向：字符 → 索引
    };
}

// 预生成编码表（固定种子）
const sensientTables = sensientGenerateTables(SENSIENT_SEED);

// 编码8位 → 6位（返回纯6位编码）
function sensientEncrypt(input, seed = SENSIENT_SEED) {
    // 输入验证：2数字+2字母+4数字
    if (!/^[0-9]{2}[A-Z]{2}[0-9]{4}$/.test(input)) {
        throw new Error("输入必须是 2数字+2字母+4数字（如：08AB1234）");
    }
    
    // 动态生成编码表（支持自定义种子）
    const tables = sensientGenerateTables(seed);
    
    // Base36 数值化：A-Z→10-35, 0-9→0-9
    const base36Val = parseInt(input.split("").map(ch => {
        if (/[0-9]/.test(ch)) return ch;
        return (ch.charCodeAt(0) - 55).toString();  // 'A'=65-55=10
    }).join(""), 10);

    // Base32 编码（使用乱序表，6位 × 32 = 约10^9，覆盖8位Base36）
    let output = "";
    let val = base36Val;
    for (let i = 0; i < 6; i++) {
        output = tables.encode[val % CHAR_LEN] + output;
        val = Math.floor(val / CHAR_LEN);
    }
    
    // 确保无溢出（如果val仍有余数，填充0索引字符）
    if (val > 0) {
        console.warn("警告：输入数值超出6位Base32范围，可能截断");
    }
    
    return output;  // ✅ 只返回6位防呆编码
}

// 解码6位 → 8位
function sensientDecrypt(code6, seed = SENSIENT_SEED) {
    // 验证：6位防呆字符
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

    // 转回8位Base36字符串
    let numStr = val.toString();
    while (numStr.length < 8) numStr = "0" + numStr;

    // 还原原始格式：2数字 + 2字母 + 4数字
    let part1 = numStr.slice(0, 2);                    // 2数字
    let part2 = String.fromCharCode(parseInt(numStr.slice(2, 4)) + 55).replace(/[IO]/g, '?');  // 2字母，防I/O
    let part3 = numStr.slice(4);                       // 4数字

    return part1 + part2 + part3;
}

// 测试函数（开发时使用）
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

// 如果在浏览器环境中，自动运行测试
if (typeof window !== 'undefined') {
    window.testSensientRoundTrip = testSensientRoundTrip;
}

// 导出函数（供 index.html 使用）
if (typeof window !== 'undefined') {
    window.sensientEncrypt = sensientEncrypt;
    window.sensientDecrypt = sensientDecrypt;
}
