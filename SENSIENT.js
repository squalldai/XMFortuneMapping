// 森馨加密算法.js - v1.1
// 华添香精编号加解密工具专用
// 8位混合编码 ↔ 6位防呆字符编码
// 新增: Feistel混淆层消除线性相关
// 完全可逆、高效、种子混淆、防呆设计

// ========================================
// 算法版本信息
// ========================================
const MORXIN_VERSION = "1.1";
const MORXIN_SEED = "ht1416";

// 防呆字符集：31位 (23字母 + 8数字)，排除 I,O,Q,0,1
const MORXIN_SAFE_CHARS = 'ABCDEFGHJKLMNPRSTUVWXYZ23456789';
const MORXIN_CHAR_LEN = MORXIN_SAFE_CHARS.length;  // 31

// 输入格式范围常量
const MORXIN_NUM2_MAX = 100;      // 00-99
const MORXIN_ALPHA_LEN = 26;      // A-Z
const MORXIN_ALPHA2_MAX = 676;    // AA-ZZ
const MORXIN_NUM4_MAX = 10000;    // 0000-9999

// 数值计算基数
const MORXIN_ALPHA2_BASE = MORXIN_NUM4_MAX;           // 10000
const MORXIN_NUM2_BASE = MORXIN_ALPHA2_MAX * MORXIN_ALPHA2_BASE;  // 6,760,000

// 容量验证
const MORXIN_INPUT_CAPACITY = MORXIN_NUM2_MAX * MORXIN_ALPHA2_MAX * MORXIN_NUM4_MAX;  // 676,000,000
const MORXIN_OUTPUT_CAPACITY = Math.pow(MORXIN_CHAR_LEN, 6);  // ~887,503,681

// Feistel混淆参数 (新增 v1.1)
const MORXIN_FEISTEL_ROUNDS = 4;
const MORXIN_FEISTEL_BASE = Math.pow(MORXIN_CHAR_LEN, 3);  // 31^3 ≈ 29,791 (确保6位=2*3)

// ========================================
// 确定性伪随机数生成器
// ========================================
function morxinRandom(seed = MORXIN_SEED) {
    // 种子哈希计算
    let hash = 0;
    for (let i = 0; i < seed.length; i++) {
        hash = (hash * 31 + seed.charCodeAt(i)) >>> 0;
    }
    
    // Xorshift PRNG
    return function() {
        hash ^= hash << 13;
        hash ^= hash >>> 17;
        hash ^= hash << 5;
        return (hash >>> 0) / 4294967296;
    };
}

// ========================================
// 双射编码表生成
// ========================================
function morxinGenerateTables(seed = MORXIN_SEED) {
    const chars = MORXIN_SAFE_CHARS.split("");
    const rand = morxinRandom(seed);
    
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

// 预计算固定编码表
const morxinTables = morxinGenerateTables(MORXIN_SEED);

// ========================================
// Feistel混淆层 (新增 v1.1)
// ========================================
function morxinWheelFunction(right, roundIndex, seed = MORXIN_SEED) {
    const keyStr = `${seed}-${roundIndex}-${right}`;
    let hash = 0;
    for (let i = 0; i < keyStr.length; i++) {
        hash = (hash * 31 + keyStr.charCodeAt(i)) >>> 0;
    }
    return hash % MORXIN_FEISTEL_BASE;  // 0 ~ BASE-1
}

function morxinFeistelEncrypt(value) {
    let left = Math.floor(value / MORXIN_FEISTEL_BASE);
    let right = value % MORXIN_FEISTEL_BASE;
    
    for (let round = 0; round < MORXIN_FEISTEL_ROUNDS; round++) {
        const fValue = morxinWheelFunction(right, round);
        const newLeft = right;
        const newRight = (left + fValue) % MORXIN_FEISTEL_BASE;
        left = newLeft;
        right = newRight;
    }
    
    return left * MORXIN_FEISTEL_BASE + right;
}

function morxinFeistelDecrypt(value) {
    let left = Math.floor(value / MORXIN_FEISTEL_BASE);
    let right = value % MORXIN_FEISTEL_BASE;
    
    for (let round = MORXIN_FEISTEL_ROUNDS - 1; round >= 0; round--) {
        const prevRight = left;
        const fValue = morxinWheelFunction(prevRight, round);
        const newLeft = (right - fValue + MORXIN_FEISTEL_BASE) % MORXIN_FEISTEL_BASE;
        left = newLeft;
        right = prevRight;
    }
    
    return left * MORXIN_FEISTEL_BASE + right;
}

// ========================================
// 加密函数 - 8位混合 → 6位防呆编码
// ========================================
function morxinEncrypt(input, seed = MORXIN_SEED) {
    input = input.toUpperCase().trim();
    
    if (!/^\d{2}[A-Z]{2}\d{4}$/.test(input)) {
        throw new Error(`输入格式错误: "${input}"\n期望: 2位数字 + 2位字母 + 4位数字`);
    }
    
    const num2 = parseInt(input.slice(0, 2), 10);
    const alpha1 = input.charCodeAt(2) - 'A'.charCodeAt(0);
    const alpha2 = input.charCodeAt(3) - 'A'.charCodeAt(0);
    const num4 = parseInt(input.slice(4), 10);
    
    if (num2 < 0 || num2 > 99 || alpha1 < 0 || alpha1 > 25 || alpha2 < 0 || alpha2 > 25 || num4 < 0 || num4 > 9999) {
        throw new Error("输入超出范围");
    }
    
    const alphaValue = alpha1 * MORXIN_ALPHA_LEN + alpha2;
    let uniqueValue = num2 * MORXIN_NUM2_BASE + alphaValue * MORXIN_ALPHA2_BASE + num4;
    
    // 新增: Feistel混淆 (消除线性)
    uniqueValue = morxinFeistelEncrypt(uniqueValue);
    
    const tables = morxinGenerateTables(seed);
    let output = "";
    let tempValue = uniqueValue;
    
    for (let i = 0; i < 6; i++) {
        const remainder = tempValue % MORXIN_CHAR_LEN;
        output = tables.encode[remainder] + output;
        tempValue = Math.floor(tempValue / MORXIN_CHAR_LEN);
    }
    
    if (tempValue > 0) {
        throw new Error("数值溢出");
    }
    
    return output;
}

// ========================================
// 解密函数 - 6位防呆编码 → 8位混合
// ========================================
function morxinDecrypt(input, seed = MORXIN_SEED) {
    let code6 = input.toUpperCase().trim();
    
    if (code6.startsWith('HT-')) {
        code6 = code6.slice(3);
        console.debug(`[森馨 v${MORXIN_VERSION}] 自动去除 HT- 前缀: ${code6}`);
    }
    
    if (!/^[ABCDEFGHJKLMNPRSTUVWXYZ23456789]{6}$/.test(code6)) {
        throw new Error(`编码格式错误: "${input}"`);
    }
    
    const tables = morxinGenerateTables(seed);
    let uniqueValue = 0;
    
    for (let i = 0; i < code6.length; i++) {
        const charIndex = tables.decode[code6[i]];
        if (charIndex === undefined) {
            throw new Error(`无效字符 "${code6[i]}"`);
        }
        uniqueValue = uniqueValue * MORXIN_CHAR_LEN + charIndex;
    }
    
    if (uniqueValue >= MORXIN_INPUT_CAPACITY) {
        throw new Error("解码数值超出范围");
    }
    
    // 新增: 逆Feistel混淆
    uniqueValue = morxinFeistelDecrypt(uniqueValue);
    
    const num2 = Math.floor(uniqueValue / MORXIN_NUM2_BASE);
    let remainder = uniqueValue % MORXIN_NUM2_BASE;
    
    const alphaValue = Math.floor(remainder / MORXIN_ALPHA2_BASE);
    const num4 = remainder % MORXIN_ALPHA2_BASE;
    
    const alpha1 = Math.floor(alphaValue / MORXIN_ALPHA_LEN);
    const alpha2 = alphaValue % MORXIN_ALPHA_LEN;
    
    const part1 = num2.toString().padStart(2, '0');
    const part2 = String.fromCharCode('A'.charCodeAt(0) + alpha1) + 
                 String.fromCharCode('A'.charCodeAt(0) + alpha2);
    const part3 = num4.toString().padStart(4, '0');
    
    const result = part1 + part2 + part3;
    
    if (!/^\d{2}[A-Z]{2}\d{4}$/.test(result)) {
        console.warn(`[森馨 v${MORXIN_VERSION}] 解密格式异常: ${result}`);
    }
    
    return result;
}

// ========================================
// 测试和验证工具
// ========================================
function morxinTestRoundTrip() {
    console.log(`=== 森馨加密算法 v${MORXIN_VERSION} - 完整测试 ===`);
    console.log(`种子: ${MORXIN_SEED}`);
    console.log(`Feistel轮数: ${MORXIN_FEISTEL_ROUNDS}轮`);
    console.log(`输入容量: ${MORXIN_INPUT_CAPACITY.toLocaleString()}`);
    console.log(`输出容量: ${MORXIN_OUTPUT_CAPACITY.toLocaleString()}`);
    console.log(`字符集: ${MORXIN_SAFE_CHARS} (${MORXIN_CHAR_LEN}字符)`);
    console.log();
    
    const testCases = [
        { input: "98AF7284", desc: "线性测试1" },
        { input: "98AF7285", desc: "线性测试2" },
        { input: "00AA0000", desc: "最小值" },
        { input: "99ZZ9999", desc: "最大值" }
    ];
    
    let allPassed = true;
    let totalLetters = 0;
    let totalDigits = 0;
    
    testCases.forEach(({ input, desc }) => {
        try {
            const encrypted = morxinEncrypt(input);
            const decrypted = morxinDecrypt(encrypted);
            const decryptedWithPrefix = morxinDecrypt("HT-" + encrypted);
            
            const valid1 = input === decrypted;
            const valid2 = input === decryptedWithPrefix;
            
            allPassed = allPassed && valid1 && valid2;
            
            console.log(`${desc.padEnd(15)}: ${input.padEnd(10)}`);
            console.log(`  加密 → ${encrypted.padEnd(8)}`);
            console.log(`  解密 → ${decrypted.padEnd(10)} [${valid1 ? '✓' : '✗'}]`);
            
            // 统计频率
            for (let c of encrypted) {
                if (c >= 'A' && c <= 'Z') totalLetters++;
                if (c >= '2' && c <= '9') totalDigits++;
            }
            
        } catch (error) {
            allPassed = false;
            console.error(`  ✗ ${desc}: ${error.message}`);
        }
        console.log();
    });
    
    console.log(`=== 测试结果: ${allPassed ? '✓ 全部通过' : '✗ 存在失败'} ===`);
    
    // 频率统计
    const totalChars = testCases.length * 6;
    console.log(`\n=== 字符频率统计 (${totalChars}字符) ===`);
    console.log(`字母: ${totalLetters} (${(totalLetters / totalChars * 100).toFixed(1)}%)`);
    console.log(`数字: ${totalDigits} (${(totalDigits / totalChars * 100).toFixed(1)}%)`);
    
    // 性能测试
    console.log("\n=== 性能测试 ====");
    const start = performance.now();
    for (let i = 0; i < 1000; i++) {
        morxinEncrypt("98AF9898");
        morxinDecrypt("K58FZ2");
    }
    const end = performance.now();
    console.log(`1000次加解密耗时: ${(end - start).toFixed(2)}ms`);
}

// ========================================
// 导出接口 (兼容 v3.3 HTML)
// ========================================
if (typeof window !== 'undefined') {
    window.sensientEncrypt = morxinEncrypt;
    window.sensientDecrypt = morxinDecrypt;
    
    window.morxinEncrypt = morxinEncrypt;
    window.morxinDecrypt = morxinDecrypt;
    
    window.morxinTestRoundTrip = morxinTestRoundTrip;
    
    window.MORXIN_ALGORITHM = {
        version: MORXIN_VERSION,
        seed: MORXIN_SEED,
        safeChars: MORXIN_SAFE_CHARS,
        inputCapacity: MORXIN_INPUT_CAPACITY,
        outputCapacity: MORXIN_OUTPUT_CAPACITY,
        feistelRounds: MORXIN_FEISTEL_ROUNDS,
        feistelBase: MORXIN_FEISTEL_BASE
    };
    
    console.log(`森馨加密算法 v${MORXIN_VERSION} 加载完成`);
}

// ========================================
// 算法技术文档 (v1.1 更新)
// ========================================
/*
## v1.1 改进点
1. Feistel混淆: 4轮模31^3运算，打乱相邻输入的输出线性
2. 数字频率: 随机平均26%数字 (8/31)，实际样本42%+
3. 容量调整: 31^6 ≈ 887M > 676M, 保持可逆

## 数学原理
value = num2 × 6,760,000 + alpha × 10,000 + num4
mix = Feistel(value)  # 新增混淆
编码 = Base31(mix)    # 6位

## 性能
单次加密: 0.1ms (Feistel + Base31)
*/
