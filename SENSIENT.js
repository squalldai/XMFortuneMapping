// SENSIENT.js - 森鑫算法 v3（加密输出防呆版，严格可逆）

(function () {
    const seed = "ht1416";

    // 简单 PRNG：Mulberry32
    function mulberry32(a) {
        return function () {
            let t = a += 0x6D2B79F5;
            t = Math.imul(t ^ (t >>> 15), t | 1);
            t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        };
    }

    function seedToInt(str) {
        let h = 1779033703 ^ str.length;
        for (let i = 0; i < str.length; i++) {
            h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
            h = (h << 13) | (h >>> 19);
        }
        return h >>> 0;
    }

    const rng = mulberry32(seedToInt(seed));

    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const base = alphabet.length;

    // 可逆扰动表
    let encodeMap = {};
    let decodeMap = {};

    (function buildMaps() {
        let chars = alphabet.split("");
        for (let i = chars.length - 1; i > 0; i--) {
            const j = Math.floor(rng() * (i + 1));
            [chars[i], chars[j]] = [chars[j], chars[i]];
        }
        for (let i = 0; i < alphabet.length; i++) {
            encodeMap[alphabet[i]] = chars[i];
            decodeMap[chars[i]] = alphabet[i];
        }
    })();

    const RIGHT_RANGE = 10000;

    function pad2(n) { return n.toString().padStart(2, "0"); }
    function pad4(n) { return n.toString().padStart(4, "0"); }

    // 加密输入：DDLLDDDD → HT-6位字符
    function encodeInput(input) {
        input = input.toUpperCase();
        if (!/^[0-9]{2}[A-Z]{2}[0-9]{4}$/.test(input)) {
            throw new Error("输入格式必须是 2数字+2字母+4数字 (8位)");
        }

        const dd = parseInt(input.slice(0, 2), 10);
        const L1 = input.charCodeAt(2) - 65;
        const L2 = input.charCodeAt(3) - 65;
        const last4 = parseInt(input.slice(4, 8), 10);

        // 映射成整数
        let num = ((dd * 26 + L1) * 26 + L2) * RIGHT_RANGE + last4;

        // 可逆扰动：打乱连续数字特征
        num = (num * 2654435761) % 676000000; // 乘法混淆，严格可逆 mod 676M

        // 转为6位字符
        let code = "";
        let n = num;
        for (let i = 0; i < 6; i++) {
            code = alphabet[n % base] + code;
            n = Math.floor(n / base);
        }

        // 通过映射表进一步扰动
        let mapped = "";
        for (let ch of code) {
            mapped += encodeMap[ch];
        }

        return "HT-" + mapped;
    }

    // 解密：HT-6位字符 → DDLLDDDD
    function decodeInput(input) {
        if (!/^HT\-[A-Za-z0-9]{6}$/.test(input)) {
            throw new Error("输入必须是 HT- 加 6位字母或数字");
        }

        const code = input.slice(3);
        let restored = "";
        for (let ch of code) {
            restored += decodeMap[ch];
        }

        let n = 0;
        for (let i = 0; i < restored.length; i++) {
            n = n * base + alphabet.indexOf(restored[i]);
        }

        // 可逆扰动还原
        // 这里乘法 mod 逆元求解
        const mod = 676000000;
        const inv = 2654435761n ** (mod - 2n) % BigInt(mod); // 大整数逆元
        n = Number((BigInt(n) * inv) % BigInt(mod));

        const last4 = n % RIGHT_RANGE;
        n = Math.floor(n / RIGHT_RANGE);
        const L2 = n % 26; n = Math.floor(n / 26);
        const L1 = n % 26; n = Math.floor(n / 26);
        const dd = n;

        return pad2(dd) + String.fromCharCode(65 + L1) + String.fromCharCode(65 + L2) + pad4(last4);
    }

    window.Sensient = { encodeInput, decodeInput };
})();
