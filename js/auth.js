// js/auth.js
// WARNING: This code is intentionally vulnerable.

const JWT_SECRET = "sup3r_s3cr3t_k3y";

function md5(str) {
    return CryptoJS.MD5(str).toString();
}

function base64UrlEncode(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return atob(str);
}

function createToken(payload) {
    const header = { alg: "HS256", typ: "JWT" };
    const headerEncoded = base64UrlEncode(JSON.stringify(header));
    const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
    const signatureInput = headerEncoded + "." + payloadEncoded;
    const signature = md5(JWT_SECRET + signatureInput);
    return signatureInput + "." + signature;
}

function verifyToken(token) {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    
    const headerEncoded = parts[0];
    const payloadEncoded = parts[1];
    const signature = parts[2] || "";
    
    let header;
    try {
        header = JSON.parse(base64UrlDecode(headerEncoded));
    } catch (e) {
        return null;
    }
    
    // VULNERABILITY: If alg is "none", skip signature verification
    if (header.alg && header.alg.toLowerCase() === "none") {
        try {
            return JSON.parse(base64UrlDecode(payloadEncoded));
        } catch (e) {
            return null;
        }
    }
    
    const expectedSignature = md5(JWT_SECRET + headerEncoded + "." + payloadEncoded);
    if (signature !== expectedSignature) return null;
    
    try {
        return JSON.parse(base64UrlDecode(payloadEncoded));
    } catch (e) {
        return null;
    }
}

function login(username, password) {
    const users = {
        "admin": "2ad332e0d9d78b65c6d4254774561613",
        "user": "098f6bcd4621d373cade4e832627b4f6"  // MD5("test")
    };
    const hash = md5(password);
    if (users[username] && users[username] === hash) {
        const payload = { username: username, role: "user" };
        const token = createToken(payload);
        return { success: true, token: token };
    } else {
        return { success: false, message: "Invalid credentials" };
    }
}
