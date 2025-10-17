# substore
完美实现了阻止 DNS 泄漏和链式代理 

使用方法

1 自行添加单条订阅（订阅可以通过添加脚本：
$server.name = '落地-' + $server.name
为节点增加前缀）

2 订阅管理页面导入sub-store组合订阅模板.json

3 在文件管理页面导入mihomo配置.json

4 custom-proxy.yaml和custom-direct.yaml分别为自定义代理和自定义直连可以根据需要自行设置

