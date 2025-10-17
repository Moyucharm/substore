// 风险节点过滤脚本（修复版）
// 来源思路：基于公开的 DC/TOR/IP 列表过滤；支持缓存（默认 6 小时）
// 可选参数（在 Script Operator → arguments 里传入）：
//   cache: true/false       // 是否启用缓存（默认 true）
//   timeout: 10000          // 单请求超时（ms）
//   retries: 3              // 失败重试次数
//   retry_delay: 2000       // 重试递增延迟（ms）
//   proxy: "http://127.0.0.1:7890" // 如需通过本地/上游代理抓取列表，可填写（可选）

async function operator(proxies, targetPlatform, context) {
  const $ = $substore;

  // --- 参数与缓存 ---
  const cacheEnabled = $arguments.cache === undefined ? true
                       : ($arguments.cache === true || String($arguments.cache).toLowerCase() === 'true');

  const CONFIG = {
    TIMEOUT: parseInt($arguments.timeout || 10000, 10),
    RETRIES: parseInt($arguments.retries || 3, 10),
    RETRY_DELAY: parseInt($arguments.retry_delay || 2000, 10)
  };

  // 脚本缓存可用性兜底
  const cache = (typeof scriptResourceCache !== 'undefined' && scriptResourceCache)
    ? scriptResourceCache
    : { get: () => null, set: () => {} };

  const cacheKey = 'risky_ips_cache_v2';
  const cacheExpiry = 6 * 60 * 60 * 1000; // 6h

  // 风险源列表
  const ipListAPIs = [
    'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt',
    'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt',
    'https://check.torproject.org/exit-addresses',
    'https://www.dan.me.uk/torlist/',
    'https://raw.githubusercontent.com/jhassine/server-ip-addresses/refs/heads/master/data/datacenters.txt'
  ];

  // 集合拆分：单 IP 与 CIDR
  let riskyIPSet = new Set();    // 形如 1.2.3.4
  let riskyCIDRs = [];           // 形如 1.2.3.0/24

  // 命中缓存直接返回
  if (cacheEnabled) {
    const cached = cache.get(cacheKey);
    if (cached?.timestamp && (Date.now() - cached.timestamp < cacheExpiry)) {
      $.info(`使用缓存数据：IP=${cached.ips?.length || 0}, CIDR=${cached.cidrs?.length || 0}`);
      riskyIPSet = new Set(cached.ips || []);
      riskyCIDRs = Array.isArray(cached.cidrs) ? cached.cidrs : [];
      return await processProxies();
    }
  }

  // --- 抓取函数 ---
  async function fetchIPList(api) {
    const options = {
      url: api,
      timeout: CONFIG.TIMEOUT,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
    };
    if ($arguments.proxy) options.proxy = String($arguments.proxy);

    let attempts = 0;
    while (attempts < CONFIG.RETRIES) {
      try {
        const res = await $.http.get(options);
        return parseList(api, res?.body || '');
      } catch (e) {
        attempts++;
        $.warn(`获取失败(${attempts}/${CONFIG.RETRIES}): ${api} -> ${e}`);
        if (attempts >= CONFIG.RETRIES) return [];
        await $.wait(CONFIG.RETRY_DELAY * attempts);
      }
    }
    return [];
  }

  // --- 解析每个源返回 ---
  function parseList(api, body) {
    if (!body) return [];
    const lines = body.split('\n').map(l => l.trim()).filter(Boolean);

    // TOR exit-addresses 特例格式
    if (api.includes('torproject.org/exit-addresses')) {
      return lines
        .filter(line => line.startsWith('ExitAddress'))
        .map(line => line.split(' ')[1])
        .filter(isIPv4Like);
    }

    // dan.me.uk/torlist/ 是纯 IP 列表
    if (api.includes('dan.me.uk/torlist/')) {
      return lines.filter(isIPv4Like);
    }

    // 通用：忽略注释
    return lines.filter(line => !line.startsWith('#'));
  }

  // --- 主抓取 ---
  try {
    const results = await Promise.all(ipListAPIs.map(fetchIPList));
    const merged = results.flat();

    for (const item of merged) {
      if (item.includes('/')) {
        // CIDR
        if (isValidCIDR(item)) riskyCIDRs.push(item);
      } else if (isIPv4Like(item)) {
        riskyIPSet.add(item);
      }
    }

    $.info(`成功更新风险列表：IP=${riskyIPSet.size}, CIDR=${riskyCIDRs.length}`);

    if (cacheEnabled) {
      cache.set(cacheKey, {
        timestamp: Date.now(),
        ips: Array.from(riskyIPSet),
        cidrs: riskyCIDRs
      });
    }
  } catch (e) {
    $.error(`更新风险列表异常：${e}`);
  }

  return await processProxies();

  // --- 处理节点 ---
  async function processProxies() {
    const out = [];
    for (const proxy of proxies) {
      try {
        // 归一化节点（有些是域名、有些是特殊结构）
        let node;
        try {
          node = ProxyUtils.produce([{ ...proxy }], 'ClashMeta', 'internal')?.[0];
        } catch (_) {}
        const serverAddr = (node && node.server) ? node.server : (proxy.server || '');

        // 只对 IPv4 地址做过滤（域名不解析，以免阻塞）
        if (isIPv4Like(serverAddr) && isRisky(serverAddr)) {
          $.info(`过滤风险节点：${proxy.name} (${serverAddr})`);
          continue; // 丢弃
        }

        out.push(proxy);
      } catch (e) {
        $.warn(`处理节点出错，已保留：${proxy.name} -> ${e}`);
        out.push(proxy); // 容错保留
      }
    }
    $.info(`处理完成：剩余 ${out.length} 个节点`);
    return out;
  }

  // --- 判定工具 ---
  function isIPv4Like(ip) {
    // 0-255 的宽松校验
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
  }

  function isValidCIDR(cidr) {
    const parts = cidr.split('/');
    if (parts.length !== 2) return false;
    const [net, bitsStr] = parts;
    if (!isIPv4Like(net)) return false;
    const bits = parseInt(bitsStr, 10);
    return Number.isInteger(bits) && bits >= 0 && bits <= 32;
  }

  function ipToInt(ip) {
    return ip.split('.').reduce((acc, o) => ((acc << 8) | (parseInt(o, 10) & 0xff)) >>> 0, 0) >>> 0;
  }

  function isIPInCIDR(ip, cidr) {
    const [net, bitsStr] = cidr.split('/');
    const bits = parseInt(bitsStr || '32', 10);
    const ipNum = ipToInt(ip);
    const netNum = ipToInt(net);
    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    return (ipNum & mask) === (netNum & mask);
  }

  function isRisky(ip) {
    if (riskyIPSet.has(ip)) return true;
    for (const c of riskyCIDRs) {
      if (isIPInCIDR(ip, c)) return true;
    }
    return false;
  }
}
