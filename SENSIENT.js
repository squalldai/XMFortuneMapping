const chars = 'ABCDEFGHJKLMNPRSTUVWXYZ23456789';

function encodeChar(c){
  if(c>='0' && c<='9') return c.charCodeAt(0)-48;
  return c.charCodeAt(0)-65+10; // A=10
}

function decodeChar(n){
  if(n<10) return String.fromCharCode(48+n);
  return String.fromCharCode(65+n-10);
}

// 将 8位输入编码为整数
function strToInt(str){
  let num=0;
  for(let i=0;i<str.length;i++){
    num=num*36+encodeChar(str[i]);
  }
  return num;
}

function intToStr(num){
  let res='';
  for(let i=0;i<8;i++){
    res=decodeChar(num%36)+res;
    num=Math.floor(num/36);
  }
  return res;
}

// 简单可逆扰动（Feistel-like）
function feistel(num, seed){
  let l=num>>>16, r=num&0xFFFF;
  let s = Array.from(seed).reduce((a,c)=>a+c.charCodeAt(0),0);
  for(let i=0;i<4;i++){
    let newL = r;
    let newR = l ^ ((r+s*i*7)&0xFFFF);
    l=newL; r=newR;
  }
  return (l<<16)+r;
}

function feistelInv(num, seed){
  let l=num>>>16, r=num&0xFFFF;
  let s = Array.from(seed).reduce((a,c)=>a+c.charCodeAt(0),0);
  for(let i=3;i>=0;i--){
    let newR = l;
    let newL = r ^ ((l+s*i*7)&0xFFFF);
    l=newL; r=newR;
  }
  return (l<<16)+r;
}

// 加密
function sensientEncrypt(str,seed='ht1416'){
  let num = strToInt(str);
  let cnum = feistel(num,seed);
  let res='';
  for(let i=0;i<6;i++){
    res+=chars[cnum%chars.length];
    cnum=Math.floor(cnum/chars.length);
  }
  return res;
}

// 解密
function sensientDecrypt(code,seed='ht1416'){
  let num=0;
  for(let i=code.length-1;i>=0;i--){
    num=num*chars.length+chars.indexOf(code[i]);
  }
  let orig = feistelInv(num,seed);
  return intToStr(orig);
}
