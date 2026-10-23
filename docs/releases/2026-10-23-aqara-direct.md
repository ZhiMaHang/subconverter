# Aqara 直连发布冒烟清单

发布日期：2026-10-23（America/Los_Angeles）。为 Aqara 品牌域名及大陆 App SDK 接口增加优先直连规则，沿用现有 `subconverter.service` 发布方式。

## 0. 发布链路与订阅刷新

- 核对 Linux x64 产物校验和，确认本机和公网 `https://sub.zhimahang.com/version` 返回待发布提交的版本。
- 先在隔离目录和备用端口验证候选二进制，再备份旧版、原子替换并重启服务；切换后检查失败则自动回滚。
- 确认服务为 `active`、`25500` 端口仅监听回环地址，部署前后的 `pref.toml` 校验和一致。
- Clash/Stash 更新订阅后才会获得新规则；公网转换入口使用已有的 `/` 路径及鉴权。

## 1. 重点回归：Aqara 直连范围

以下规则位于其他站点规则、rule-provider 和 MATCH 之前，原有 NGA 等直连策略继续保留：

```text
DOMAIN-SUFFIX,aqara.com,DIRECT
DOMAIN-SUFFIX,aqara.cn,DIRECT
DOMAIN-SUFFIX,aqara.com.cn,DIRECT
DOMAIN-SUFFIX,lumiunited.com,DIRECT
DOMAIN,aiot-rpc.ankasa.cn,DIRECT
```

- 检查 `open-cn.aqara.com`、`aiot-coap.aqara.cn` 等官方云接口和四个品牌域名的子域命中 DIRECT。
- 检查 `aiot-rpc.ankasa.cn` 精确匹配；`ankasa.cn`、其他主机和该接口的子域保留原有策略。
- 相似域名如 `notaqara.com`、`aqara.com.example` 保留原有规则；同域代理/REJECT 冲突规则会归一化且不重复。
- 自动回归覆盖 Clash/ClashR/Stash、展开规则、rule-provider、关闭规则生成、旧 `Rule` 字段与 Clash script；脚本检查精确域名、大小写、子域边界及 provider 优先级。

## 2. 客户端与回滚

更新订阅后，在客户端连接日志确认 Aqara 请求命中 DIRECT，再检查 App 登录和设备控制。自动化检查验证生成的路由配置，实际设备控制由客户端网络和设备状态共同决定。

发布时保存旧版二进制的回滚文件路径；恢复后重启 `subconverter.service`，核对版本并重跑转换检查。

域名依据：[官方云服务接口表](https://opendoc.aqara.com/en/docs/developmanual/apiIntroduction/APIUsageGuide.html)、[中国官网](https://www.aqara.com.cn/service_provider)、[绿米官网](https://www.lumiunited.com/cn/index)。
