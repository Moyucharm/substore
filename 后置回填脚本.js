// [Post] 将 $server._keepTags 贴回节点名末尾，并去重
(function () {
  const keep = Array.isArray($server._keepTags) ? $server._keepTags : [];
  if (!keep.length) return;

  const base = String($server.name || "");
  const have = new Set(base.toLowerCase().split(/\s+/));
  const tail = keep.filter(t => !have.has(String(t).toLowerCase()));

  if (tail.length) {
    $server.name = (base + " " + tail.join(" ")).replace(/\s{2,}/g, " ").trim();
  }
  delete $server._keepTags;
})();
