# NGA 直连发布冒烟清单

发布日期：2026-10-22（America/Los_Angeles）。本次为 NGA 论坛、图片资源和兼容入口增加优先直连规则。部署沿用现有 `subconverter.service`，替换前先隔离验证候选二进制并备份线上版本。

## 0. 发布链路与订阅刷新

- 核对 Linux x64 构建产物与校验和，确认线上 `/version` 的提交号与待发布产物一致。
- 确认 `subconverter.service` 为 `active`，`127.0.0.1:25500` 正常应答，公网 `https://sub.zhimahang.com/version` 返回相同版本。
- 核对部署前后的 `pref.toml` 校验和一致，并保存旧二进制回滚路径。
- 在 Clash/Stash 中更新订阅，确认下载的是本次生成的配置。旧配置要更新后才会包含新规则。

## 1. 重点回归：NGA 直连

检查完整 Clash、ClashR 和 Stash 配置中的以下规则位于其他站点规则、rule-provider 和 MATCH 之前：

```text
DOMAIN-SUFFIX,nga.cn,DIRECT
DOMAIN-SUFFIX,ngabbs.com,DIRECT
DOMAIN-SUFFIX,ngacn.cc,DIRECT
DOMAIN-SUFFIX,nga.178.com,DIRECT
```

- 打开 `bbs.nga.cn`，并检查 `img4.nga.cn`、`img8.nga.cn` 等资源请求命中 DIRECT。
- 检查另外三个入口及其子域采用相同直连策略；`ngacn.cc` 用于兼容旧入口，规则验证不代表网站当前可用。
- 使用外部配置中已有的代理/REJECT 冲突规则生成订阅，确认同域规则被规范化且不重复。
- 检查 `178.com`、`other.178.com`、`notnga.cn`、`nga.cn.example` 继续保留原有策略，NGA 规则只匹配根域和点分隔子域。

## 2. 已自动验证的项目

- 后端四组 C++ 回归测试：VLESS/Stash、Clash DoH、混合订阅、托管服务规则。
- 前端四项 Node.js 测试。
- 实际生成的 Clash 路由脚本：39 个大小写、子域、相似域名、provider 优先级场景通过。
- 输出模式覆盖展开规则、rule-provider、关闭规则生成、旧 `Rule` 字段及 Clash script。

## 3. 回滚与使用说明

发布脚本在原子替换前备份旧二进制，替换后健康检查失败会恢复旧版并重启 `subconverter.service`。手工回滚时使用本次记录的回滚文件，恢复后核对 `/version`，再重新运行订阅转换检查。

用户侧说明：更新订阅后 NGA 将优先直连；代理客户端中手工覆盖规则、全局模式及站点本身的网络状态需要在客户端单独确认。
