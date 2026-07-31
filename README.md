# CTF Arena Factory v0.6

## Visual CTF Studio

Launch the local designer and open `http://127.0.0.1:8787`:

```powershell
python -m ctf_factory.cli studio
```

Set `LLM_API_KEY` (or `OPENAI_API_KEY`) to use ChatGPT as the design brain. Without a key,
the Studio uses a deterministic offline planner. The AI may select and customize reviewed
templates, but bundle generation, flags, solvers, and release gates remain local and deterministic.

面向**授权、本地沙箱**的 AI 辅助 CTF 出题 Agent。AI 只负责主题文案，漏洞、密码学弱点、证据构造和 Solver 均来自审核模板，因此生成结果可复现、可测试。

## 题型矩阵

| 类别 | 类型 | 交付形式 |
|---|---|---|
| Web | `path-normalization` | Docker Web 服务 |
| Web | `weak-session` | Docker Web 服务 |
| Web | `query-injection` | Docker Web 服务 |
| Reverse | `xor-strings` | 混淆字符串制品 |
| Reverse | `bytecode-vm` | 自定义 VM 字节码 |
| Reverse | `license-check` | 校验表逆向 |
| Pwn | `stack-overflow-sim` | 离线栈内存模拟 |
| Pwn | `format-string-sim` | 格式化字符串栈模拟 |
| Pwn | `integer-overflow-sim` | 固定位宽整数模拟 |
| Crypto | `repeating-xor` | 静态附件 |
| Crypto | `weak-rsa` | 静态附件 |
| Crypto | `lcg-stream` | 静态附件 |
| Forensics | `log-fragments` | 日志证据包 |
| Forensics | `zip-recovery` | 损坏的 ZIP 证据 |
| Forensics | `packet-timing` | 数据包时间线 CSV |
| Misc | `ppm-lsb` | PPM 图像隐写 |
| Misc | `whitespace-code` | 空白字符隐写 |
| Misc | `encoding-matryoshka` | 多层编码信号 |
| Blockchain | `storage-slots` | 合约存储快照 |
| Blockchain | `event-log` | 链上事件日志 |
| Blockchain | `nonce-reuse` | 玩具签名样本 |
| AI/ML | `prompt-injection` | 模拟 Agent 追踪证据 |
| AI/ML | `rag-poisoning` | 离线检索语料库 |
| AI/ML | `model-extraction` | 小型线性模型查询样本 |
| IoT | `firmware-strings` | 固件镜像 |
| IoT | `uart-fragments` | UART 启动日志 |
| IoT | `mqtt-retain` | MQTT 消息捕获 |
| Mobile | `android-manifest` | APK 组件审计 |
| Mobile | `dex-obfuscation` | Smali 字符串逆向 |
| Mobile | `native-library` | JNI 原生逻辑逆向 |

每个类型支持 `easy`、`medium`、`hard`，共 **90 种组合**。

难度不是单纯标签：更高难度会增加编码/干扰层、解题步骤并减少提示。每次生成都会使用随机 Flag，并自动运行组织者 Solver；Solver 无法还原 Flag 时不会发布题包。

## 查看可用题型

```powershell
python -m ctf_factory.cli list
```

## 生成题目

```powershell
python -m ctf_factory.cli generate `
  --category web `
  --type weak-session `
  --difficulty medium `
  --theme "太空站身份系统" `
  --output generated
```

Crypto 示例：

```powershell
python -m ctf_factory.cli generate --category crypto --type weak-rsa --difficulty hard --theme "卫星通信"
```

Forensics 示例：

```powershell
python -m ctf_factory.cli generate --category forensics --type packet-timing --difficulty medium --theme "异常网络流量"
```

AI/ML 示例：

```powershell
python -m ctf_factory.cli generate --category ai-ml --type rag-poisoning --difficulty hard --theme "企业知识助手"
```

## 本地攻防回合

当前 `arena` 支持三个 Web 模板。它只处理生成的本地题包，不连接或攻击外部目标：

```powershell
python -m ctf_factory.cli arena generated\web-query-injection-hard
```

攻防流程：

1. Attacker 验证原始模板的 intended exploit。
2. Defender 应用与模板绑定的审核补丁。
3. Judge 确认原 exploit 被阻断。
4. Judge 编译补丁服务并检查正常功能入口仍存在。
5. 输出 `arena-report.json` 和 0–100 分结果。

防守版本输出到题包的 `defended/app.py`。当前攻防裁判基于审核模板语义，不是针对任意真实网站的自动渗透工具。

## 题包结构

```text
generated/<题目>/
├── challenge.json       # 公开元数据，不含 Flag
├── README.md            # 给选手的题面和提示
├── player/              # 交付给选手的服务或证据
└── organizer/
    ├── spec.json        # 完整规格与 Flag，仅组织者保存
    └── solver.py        # 自动可解性验证器
```

Web 题额外包含 `Dockerfile` 和 `docker-compose.yml`：

```powershell
cd generated\web-weak-session-medium
docker compose up --build
```

## 可选 AI 文案

未配置模型时完全离线运行。配置 OpenAI-compatible API 后，模型只会改写不含解法的故事文案，不会生成未经审核的攻击代码：

```powershell
$env:LLM_API_KEY="你的密钥"
$env:LLM_BASE_URL="https://api.openai.com/v1"
$env:LLM_MODEL="gpt-4.1-mini"
```

不要把 API 密钥写进项目或提交到 GitHub。

## 发布门禁

1. 类别和题型必须在 allow-list 中。
2. 难度必须经过校准。
3. 公开元数据不能包含 Flag。
4. 禁止真实外部目标、私钥或疑似云凭据。
5. 每个题包必须包含选手材料、组织者规格和 Solver。
6. Solver 必须在 15 秒内精确恢复本次随机 Flag。

## 测试

```powershell
python -m unittest discover -s tests -v
```

测试会生成并求解全部 90 种组合，并验证三个 Web 模板的攻防补丁回归。

## 安全边界

- 仅用于本地或隔离 Docker 网络。
- 不攻击比赛平台、其他队伍或第三方系统。
- 新题型必须先增加审核模板和 Solver，再加入 allow-list。
- `organizer/` 不可发给选手。
