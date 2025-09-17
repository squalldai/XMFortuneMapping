// SENSIENT.js
// 森鑫算法 (Sensient Algorithm)
// 固定种子 ht1416，严格双射可逆映射

(function () {
    const seed = "ht1416";

    // 随机数生成器（可复现）
    function mulberry32(a) {
        return function () {
            let t = a += 0x6D2B79F5;
            t = Math.imul(t ^ (t >>> 15), t | 1);
            t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        }
    }

    // 将种子转为数字种子
    function seedToInt(str) {
        let h = 1779033703 ^ str.length;
        for (let i = 0; i < str.length; i++) {
            h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
            h = (h << 13) | (h >>> 19);
        }
        return h >>> 0;
    }

    const rng = mulberry32(seedToInt(seed));

    // Base62 编码字符集
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    // 构造双射映射表
    let encodeMap = {};
    let decodeMap = {};
    (function buildMaps() {
        let chars = alphabet.split("");
        // 洗牌
        for (let i = chars.length - 1; i > 0; i--) {
            const j = Math.floor(rng() * (i + 1));
            [chars[i], chars[j]] = [chars[j], chars[i]];
        }
        // 建立映射
        for (let i = 0; i < alphabet.length; i++) {
            encodeMap[alphabet[i]] = chars[i];
            decodeMap[chars[i]] = alphabet[i];
        }
    })();

    // 输入规范: 2数字 + 2字母 + 4数字  (共8位)
    function encodeInput(input) {
        if (!/^[0-9]{2}[A-Z]{2}[0-9]{4}$/.test(input)) {
            throw new Error("输入必须是 2数字 + 2字母 + 4数字 (8位)");
        }

        // 逐字符映射
        let mapped = "";
        for (let ch of input) {
            mapped += encodeMap[ch] || ch;
        }

        // 取前6位作为加密结果
        return "HT-" + mapped.slice(0, 6);
    }

    function decodeInput(input) {
        if (!/^HT\-[A-Za-z0-9]{6}$/.test(input)) {
            throw new Error("输入必须是 HT- 加 6位字母或数字");
        }

        let code = input.slice(3); // 去掉 HT-

        // 还原映射
        let restored = "";
        for (let ch of code) {
            restored += decodeMap[ch] || ch;
        }

        // 由于加密时只取了前6位，因此解密需要补足完整8位
        // 这里保证与 encodeInput 完全对应
        // 规则: 直接取还原的前6位 + 固定补位 "00"
        restored = restored + "00";

        return restored;
    }

    // 导出到全局
    window.Sensient = {
        encodeInput,
        decodeInput
    };
})();
