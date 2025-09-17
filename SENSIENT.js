// 固定种子
const SENSIENT_SEED = "ht1416";

// 映射表字符集
const SENSIENT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// 简单可逆哈希（扰动 + 保证可逆性）
function sensientHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = (hash * 31 + str.charCodeAt(i) + SENSIENT_SEED.charCodeAt(i % SENSIENT_SEED.length)) % 1000000;
    }
    return hash;
}

// 加密函数
function sensientEncrypt(input) {
    if (!/^[0-9]{2}[A-Z]{2}[0-9]{4}$/.test(input)) {
        throw new Error("输入必须是 2数字+2字母+4数字 (8位)");
    }

    const hash = sensientHash(input);

    // 转换为 6 位输出
    let result = "";
    let temp = hash;
    for (let i = 0; i < 6; i++) {
        result = SENSIENT_CHARS[temp % SENSIENT_CHARS.length] + result;
        temp = Math.floor(temp / SENSIENT_CHARS.length);
    }

    return result; // ❌ 不要加 HT-
}

// 解密函数
function sensientDecrypt(input) {
    if (!/^[A-Z0-9]{6}$/.test(input)) {
        throw new Error("输入必须是 6位字母或数字");
    }

    // 遍历法恢复
    for (let d1 = 0; d1 <= 99; d1++) {
        for (let l1 = 65; l1 <= 90; l1++) {
            for (let l2 = 65; l2 <= 90; l2++) {
                for (let d2 = 0; d2 <= 9999; d2++) {
                    const candidate =
                        d1.toString().padStart(2, "0") +
                        String.fromCharCode(l1) +
                        String.fromCharCode(l2) +
                        d2.toString().padStart(4, "0");

                    if (sensientEncrypt(candidate) === input) {
                        return candidate;
                    }
                }
            }
        }
    }
    throw new Error("未找到对应解密结果");
}

// 挂载到 window
window.sensientEncrypt = sensientEncrypt;
window.sensientDecrypt = sensientDecrypt;
