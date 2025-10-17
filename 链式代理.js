// 自动给所有名称包含“落地”或“家宽”的节点添加 dialer-proxy: "⚙️ 节点选择"
// 适用于 Sub-Store JS 处理（需支持自定义 JS 处理功能）

function main({ proxies }) {
  // 需要匹配的关键词，可自行添加
  const keywords = [/落地/i, /家宽/i];

  for (const proxy of proxies) {
    if (!proxy.name) continue;
    // 检查是否匹配关键词
    if (keywords.some(reg => reg.test(proxy.name))) {
      // 避免重复添加
      if (!proxy["dialer-proxy"]) {
        proxy["dialer-proxy"] = "⚙️ 节点选择";
      }
    }
  }

  // 返回对象，Sub-Store 会自动合成最终 YAML
  return { proxies };
}
