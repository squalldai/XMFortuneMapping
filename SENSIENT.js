// SENSIENT.js - 兼容性修复版本
// 香精编号加密算法：8位混合 → 6位防呆字符
// 完全可逆、全大写、防呆设计、确定性加密
// 兼容：sensientDecrypt 支持 "HT-XXXXXX" 和纯 "XXXXXX" 两种输入格式

// ========================================
// 常量定义
// ========================================
const SENSIENT_SEED = "ht1416";

// 防呆字符集：32字符，排除易混淆字符 (I, O, Q, 0, 1)
const SAFE_CHARS = 'ABCDEFGHJKLMNPRSTUVWXYZ23456789';
const CHAR_LEN = SAFE_CHARS.length;  // 32

// ========================================
// 伪随机数生成器
// ========================================
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
    };
}

// ========================================
// 编码表生成
// ========================================
function sensientGenerateTables(seed = SENSIENT_SEED) {
    const chars = SAFE_CHARS.split("");
    const rand = sensientRandom(seed);
    
    // Fisher-Yates 洗牌
    for (let i = chars.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    
    const decodeMap = chars.reduce((map, char, index) => {
        map[char] = index;
        return map;
    }, {});
    
    return {
        encode: chars,
        decode: decodeMap
    };
}

const sensientTables = sensientGenerateTables(SENSIENT_SEED);

// ========================================
// 加密函数（不变）
// ========================================
function sensientEncrypt(input, seed = SENSIENT_SEED) {
    input = input.toUpperCase().trim();
    if (!/^\d{2}[A-Z]{2}\d{4}$/.test(input)) {
        throw new Error("输入格式错误：必须是 2数字 + 2字母 + 4数字\n示例：98AF9898");
    }
    
    // Base36 数值化
    let value = 0;
    for (let i = 0; i < input.length; i++) {
        const char = input[i];
        let charValue;
        
        if (/\d/.test(char)) {
            charValue = parseInt(char, 10);
        } else {
            charValue = char.charCodeAt(0) - 'A'.charCodeAt(0) + 10;
        }
        
        if (charValue < 0 || charValue > 35) {
            throw new Error(`无效字符: ${char} (位置 ${i + 1})`);
        }
        
        value = value * 36 + charValue;
    }
    
    // Base32 编码
    const tables = sensientGenerateTables(seed);
    let output = "";
    
    for (let i = 0; i < 6; i++) {
        const remainder = value % CHAR_LEN;
        output = tables.encode[remainder] + output;
        value = Math.floor(value / CHAR_LEN);
    }
    
    if (value > 0) {
        console.warn("警告：输入数值超出6位Base32范围，已截断");
    }
    
    return output;  // 返回纯6位编码
}

// ========================================
// 解密函数（兼容性修复）
// ========================================
// 支持两种输入格式：
// 1. "HT-43W54X" (9位，带前缀)
// 2. "43W54X" (6位，纯编码)
function sensientDecrypt(input, seed = SENSIENT_SEED) {
    // 1. 输入标准化
    let code6 = input.toUpperCase().trim();
    
    // 2. 智能去除 "HT-" 前缀（兼容性处理）
    if (code6.startsWith('HT-')) {
        code6 = code6.substring(3);  // "HT-43W54X" → "43W54X"
        console.log(`[SENSIENT] 检测到 HT- 前缀，已自动去除: ${code6}`);
    }
    
    // 3. 严格验证：必须是6位防呆字符
    if (!/^[ABCDEFGHJKLMNPRSTUVWXYZ23456789]{6}$/.test(code6)) {
        throw new Error(`输入格式错误：${input}\n` +
                       `期望格式：\n` +
                       `• 6位防呆编码（如：43W54X）\n` +
                       `• 或 HT- + 6位编码（如：HT-43W54X）\n` +
                       `合法字符：${SAFE_CHARS}`);
    }
    
    // 4. Base32 解码
    const tables = sensientGenerateTables(seed);
    let value = 0;
    
    for (let i = 0; i < code6.length; i++) {
        const char = code6[i];
        const charIndex = tables.decode[char];
        
        if (charIndex === undefined) {
            throw new Error(`无效字符: ${char} (位置 ${i + 1})\n合法字符：${SAFE_CHARS}`);
        }
        
        value = value * CHAR_LEN + charIndex;
    }
    
    // 5. Base36 字符串化（全大写）
    let base36Str = value.toString(36).toUpperCase();
    
    // 6. 补零到8位，确保格式一致
    base36Str = base36Str.padStart(8, '0');
    
    // 7. 取最后8位（防止溢出）
    base36Str = base36Str.slice(-8);
    
    // 8. 验证输出格式
    if (!/^\d{2}[A-Z0-9]{2}\d{4}$/.test(base36Str)) {
        console.warn(`解密结果格式异常: ${base36Str} (原始值: ${value})`);
    }
    
    return base36Str;  // 返回8位原始格式
}

// ========================================
// 测试和调试工具
// ========================================
function testSensientRoundTrip() {
    console.log("=== SENSIENT 算法完整测试（兼容性版本）===");
    console.log(`种子: ${SENSIENT_SEED}`);
    console.log(`字符集: ${SAFE_CHARS} (${CHAR_LEN}字符)`);
    console.log();
    
    const testCases = [
        { input: "08AB1234", desc: "标准测试1" },
        { input: "98AF9898", desc: "你的测试用例" },
        { input: "12CD5678", desc: "标准测试2" },
        { input: "99ZZ9999", desc: "边界测试" }
    ];
    
    testCases.forEach(({ input, desc }) => {
        try {
            const encrypted = sensientEncrypt(input);
            const decrypted = sensientDecrypt(encrypted);
            const decryptedWithPrefix = sensientDecrypt('HT-' + encrypted);
            
            const isValid = input === decrypted;
            const isValidWithPrefix = input === decryptedWithPrefix;
            
            console.log(`${desc.padEnd(15)}: ${input}`);
            console.log(`  加密 → ${encrypted}`);
            console.log(`  解密(纯6位) → ${decrypted} [${isValid ? '✓' : '✗'}]`);
            console.log(`  解密(HT-前缀) → ${decryptedWithPrefix} [${isValidWithPrefix ? '✓' : '✗'}]`);
            console.log();
        } catch (error) {
            console.error(`测试失败 ${desc}: ${input}`);
            console.error(`错误: ${error.message}`);
            console.log();
        }
    });
    
    // 验证你的具体问题
    console.log("=== 验证你的具体问题 ===");
    try {
        const result = sensientDecrypt("HT-43W54X");
        const reEncrypted = sensientEncrypt(result);
        console.log(`HT-43W54X → ${result}`);
        console.log(`重新加密 → ${reEncrypted}`);
        console.log(`是否匹配 → ${reEncrypted === "43W54X" ? "✓ 是" : "✗ 否"}`);
        console.log(`期望结果 → 98AF9898 [${result === "98AF9898" ? "✓ 正确" : "✗ 错误"}]\n`);
    } catch (error) {
        console.error(`验证失败: ${error.message}\n`);
    }
}

// 验证特定编码的工具函数
function verifySpecificCode(code6, expected = null) {
    console.log(`=== 验证编码: ${code6} ===`);
    try {
        const decrypted = sensientDecrypt(code6);
        const encrypted = sensientEncrypt(decrypted);
        
        console.log(`解密结果: ${decrypted}`);
        console.log(`重新加密: ${encrypted}`);
        console.log(`是否自洽: ${code6.includes('HT-') ? 'HT-' + encrypted : encrypted} === ${code6 ? code6 : 'HT-' + code6}`);
        console.log(`原始格式: ${/^\d{2}[A-Z]{2}\d{4}$/.test(decrypted) ? '✓ 正确' : '✗ 错误'}`);
        
        if (expected) {
            console.log(`期望结果: ${expected} [${decrypted === expected ? '✓ 匹配' : '✗ 不匹配'}]`);
        }
        
        console.log();
    } catch (error) {
        console.error(`验证失败: ${error.message}\n`);
    }
}

// ========================================
// 导出接口
// ========================================
if (typeof window !== 'undefined') {
    window.sensientEncrypt = sensientEncrypt;
    window.sensientDecrypt = sensientDecrypt;
    window.testSensientRoundTrip = testSensientRoundTrip;
    window.verifySpecificCode = verifySpecificCode;
    
    window.SENSIENT_DEBUG = {
        SEED: SENSIENT_SEED,
        CHARS: SAFE_CHARS,
        TABLES: sensientTables,
        CAPACITY: Math.pow(CHAR_LEN, 6)
    };
    
    // 开发环境自动测试
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        setTimeout(() => {
            console.log("开发环境检测，3秒后自动运行测试...");
            setTimeout(testSensientRoundTrip, 3000);
        }, 1000);
    }
}
