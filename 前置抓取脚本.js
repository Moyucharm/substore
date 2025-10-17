// [Pre] 捕获括号中的标签并暂存到 $server._keepTags
// 可选参数：arguments.allow = "DMIT|IPLC|IEPL|CN2|AS9929"（留空=全保留）

(function () {
  const raw = String($server.name || "");
  const allow = String($arguments.allow || "").trim();
  const allowRe = allow ? new RegExp("(" + allow + ")", "i") : null;

  // 支持：()（）[]【】《》<>「」『』
  const regs = [
    /\(([^()]{1,64})\)/g, /（([^（）]{1,64})）/g,
    /\[([^\[\]]{1,64})\]/g, /【([^【】]{1,64})】/g,
    /《([^《》]{1,64})》/g, /<([^<>]{1,64})>/g,
    /「([^「」]{1,64})」/g, /『([^『』]{1,64})』/g
  ];

  let tags = [];
  for (const re of regs) {
    let m;
    while ((m = re.exec(raw))) {
      const t = (m[1] || "").trim();
      if (!t) continue;
      if (allowRe && !allowRe.test(t)) continue; // 白名单
      tags.push(t);
    }
  }

  if (tags.length) {
    const seen = new Set();
    tags = tags.filter(x => {
      const k = x.toLowerCase();
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    $server._keepTags = tags;
  }
})();
