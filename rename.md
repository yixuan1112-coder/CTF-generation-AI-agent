# CTF Generation AI Agent 使用与上线手册

本文档对应当前 `main` 分支的 v0.8 架构，说明如何启动出题前端、使用执行式进化 Agent、验证题目、启动选手界面、导出题包，以及将题目部署到比赛环境。

> 仅限本机、教学靶场、比赛基础设施或明确授权环境。不要把生成的攻击逻辑用于第三方系统。

## 1. 当前架构

```text
Browser Studio :8787
        │
        ├── Optional OpenAI-compatible design brain
        │
        ├── Generator: 产生第一代候选
        │
        ├── Executable Evaluator
        │     ├── 构建完整临时题包
        │     ├── 官方 Solver 连续执行两次
        │     ├── 导出泄漏与通用捷径探测
        │     └── 运行时编译和导入探测
        │
        ├── Breaker + Judge
        │
        ├── Mutator: 根据反馈生成第二代
        │
        ├── SQLite episodic memory
        │
        └── Docker Runner
              ├── HTTP player workspace
              ├── TCP / nc
              ├── MQTT
              ├── JSON-RPC
              └── Attachment / Mobile analysis workspace
```

这不是会无限自我修改的 GAN。它是有边界的 Generator–Solver–Breaker–Judge–Mutator 系统：

- 只能使用审核过的 30 个构建原语。
- 默认运行两代，每代 3 个候选。
- 第二代根据第一代的执行结果变异。
- Agent 不能修改自身源代码或绕过发布门禁。
- 最终上线仍应由出题人审核。

## 2. 环境准备

需要安装：

- Python 3.11 或更高版本
- Docker Desktop
- Git
- 可选：OpenAI API Key
- 可选：Ncat、`mosquitto_sub`、Android SDK、Jadx、Ghidra

进入项目目录：

```powershell
cd "C:\Users\41604\Documents\AI agent for CTF"
```

检查环境：

```powershell
python -m ctf_factory.cli doctor
```

运行全部测试：

```powershell
python -m unittest discover -s tests -v
```

## 3. 配置 AI API Key

ChatGPT 登录和 ChatGPT Plus 订阅不能直接作为 API Key。需要单独使用 OpenAI Platform API Key。

Windows 推荐执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\configure-openai.ps1
```

脚本会配置：

```text
OPENAI_API_KEY
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-5-mini
```

配置后关闭旧 Studio 进程并重新启动。API 调用失败时，系统会自动使用 Offline Brain；执行式构建、Solver、Breaker、变异和记忆仍会运行。

## 4. 打开出题前端

启动 Docker Desktop，然后运行：

```powershell
python -m ctf_factory.cli studio --port 8787
```

浏览器打开：

```text
http://127.0.0.1:8787/
```

保持 PowerShell 窗口运行。浏览器仍显示旧代码时按 `Ctrl + F5`。

## 5. 使用进化 Agent 出题

1. 选择 CTF Domain。
2. 选择具体 Challenge Type。
3. 选择 Easy、Medium 或 Hard。
4. 在 Creative Brief 中写入题目背景、希望考查的知识和预期风格。
5. 点击 **Ask AI to create the blueprint**。
6. 等待候选构建、Solver 执行、Breaker 探测和第二代变异。
7. 检查胜出题目的标题、故事、提示、mechanics 和 Evaluation。
8. 设置唯一的 Variant；需要复现时填写 Seed。
9. 点击 **Build, solve, and audit bundle**。
10. 点击 **Launch instance** 打开选手工作台。

默认一次规划会：

```text
3 个第一代候选
+ 3 个第二代变异候选
= 6 个真实构建并执行的临时题包
```

在线模型只设计第一代，第二代由本地 Mutator 根据执行证据产生，因此默认是 3 次模型调用，而不是 6 次。

## 6. Evaluation 分数含义

Evaluation 不是装饰性比赛分值，而是发布前工程质量分：

| 维度 | 证据 |
|---|---|
| Execution | 官方 Solver 是否连续两次恢复正确 Flag |
| Adversarial Resistance | 是否泄漏 Flag，是否存在低于难度预期的通用捷径 |
| Determinism | 重复运行 Solver 的输出是否一致 |
| Runtime Integrity | 运行入口是否能够编译、导入和读取公开题目信息 |
| Novelty | 与历史题面、提示和 mechanics 的相似度 |
| Clarity | 题面目标是否足够清晰 |
| Mutation Gain | 第二代是否比父代的执行评估更好 |

前端还会显示：

- `G0`：第一代候选
- `G1`：第二代变异候选
- Winner generation
- Improvement over initial
- Executed bundles
- Historical episodes retrieved

最终题包的详细证据写在：

```text
generated\<challenge-slug>\quality.json
```

## 7. 记忆如何工作

长期记忆默认位于：

```text
.ctf-agent\memory.sqlite3
```

保存的是脱敏 episode：

- Category、Challenge Type、Difficulty
- Candidate signature
- Run ID、Generation、Parent signature
- Mechanics
- Solver 时间和构建时间
- 通用捷径深度
- Gate 数量
- 评分、风险和脱敏经验

不会保存：

- OpenAI API Key
- 真实 Flag
- 组织者完整秘密

查看统计：

```powershell
python -m ctf_factory.cli memory
```

下一次生成相同题型时，系统会检索历史 episode：

- 相似方案降低 Novelty。
- 过去的风险会进入 Generator 上下文。
- Mutator 会参考历史 mechanics，提高或改变编码深度、干扰密度和推理阶段。

## 8. 支持的交互方式

| 方向 | 浏览器工作台 | 保留的原生方式 |
|---|---|---|
| Web | 漏洞应用和请求构造器 | HTTP |
| AI / LLM | 聊天攻击和 Flag 提交 | HTTP API |
| Pwn | 证据预览和网页终端 | `nc host port` |
| Blockchain | 合约证据和 RPC 控制台 | JSON-RPC |
| IoT | 设备证据和消息控制台 | MQTT |
| Crypto | 附件下载、文本/Hex 预览 | Python、SageMath 等 |
| Reverse | 二进制/字节码预览和下载 | Ghidra、IDA 等 |
| Forensics | 日志、归档、流量证据工作台 | Wireshark、Volatility 等 |
| Misc | 图片、文本和编码证据工作台 | 对应分析工具 |
| Mobile | APK、Smali、JNI 工作台 | ADB、Emulator、Jadx |

静态附件题仍然需要选手真正分析附件；网页工作台只负责交付、预览和 Flag 验证，不会替代专业工具。

## 9. 启动和停止一道题

### 前端启动

生成完成后点击：

```text
Launch instance
```

系统会：

1. 校验题目是否位于 `generated/`。
2. 校验 `challenge.json`、`runtime.json` 和 Docker 配置。
3. 构建隔离容器。
4. 绑定到 `127.0.0.1` 动态端口。
5. 打开浏览器工作台。
6. 对 Pwn、MQTT 等题同时显示原生命令。

### 手动启动

```powershell
cd generated\<challenge-slug>
docker compose up -d --build
docker compose ps
```

查看日志：

```powershell
docker compose logs -f
```

停止：

```powershell
docker compose down
```

## 10. 验证题目确实可解

不要只相信 Evaluation 数字。正式发布前至少执行：

```powershell
cd generated\<challenge-slug>
python .\organizer\solver.py
```

输出必须是一个 `flag{...}`。

Web 题还可以运行 Attack–Defend–Judge：

```powershell
python -m ctf_factory.cli arena generated\<web-challenge-slug>
```

检查：

- 官方攻击在漏洞版本成功。
- 修补后攻击失败。
- 正常功能在修补前后都可使用。
- `arena-report.json` 的 `passed` 为 `true`。

还应由人工选手进行盲测，确认：

- 没有非预期秒杀。
- 提示顺序合理。
- 难度与比赛定位一致。
- 浏览器、原生协议和附件均能正常使用。

## 11. 题包目录

```text
generated/<challenge-slug>/
├── README.md
├── challenge.json
├── quality.json
├── runtime.json
├── deployment.json
├── Dockerfile
├── docker-compose.yml
├── player/
└── organizer/
    ├── spec.json
    └── solver.py
```

安全边界：

- `player/`：选手界面、附件或服务代码。
- `organizer/spec.json`：真实 Flag 和完整规格，必须保密。
- `organizer/solver.py`：官方解法，比赛前必须保密。
- 不要公开完整 `generated/` 目录。

## 12. 导出选手包

```powershell
python -m ctf_factory.cli export generated\<challenge-slug>
```

输出位于：

```text
exports\<challenge-slug>-player.zip
```

导出器会：

- 排除 `organizer/`
- 排除明文 `player/flag.txt`
- 对服务类题目使用部署占位 Flag 重建
- 保留静态题目真正需要分析的证据

发布前建议解压 ZIP 并再次搜索真实 Flag，确认没有明文泄漏。

## 13. 上线到比赛服务器

### 单机 Docker 上线

将审核通过的题目目录复制到比赛服务器，然后：

```bash
cd generated/<challenge-slug>
docker compose up -d --build
docker compose ps
```

不要直接公开随机 Docker 端口。生产环境应通过 CTF 平台或反向代理分配实例地址。

### 推荐生产结构

```text
HTTPS Reverse Proxy
        │
        ├── CTF Platform / Auth / Rate Limit
        │
        ├── Studio API
        │     ├── PostgreSQL
        │     ├── Redis task queue
        │     └── S3/R2/OSS player artifacts
        │
        └── Isolated Docker Runner pool
              └── Per-team ephemeral instances
```

生产环境必须增加：

- HTTPS
- 登录和角色权限
- 每用户生成与启动限额
- 审计日志
- 容器 CPU、内存、PID、磁盘和时间限制
- 独立 Runner 主机
- 网络出口限制
- Flag 按队伍或实例动态生成
- 实例过期自动销毁

当前仓库的 Studio 默认绑定 `127.0.0.1`，是本地出题与验证工具，不应直接作为公网多用户服务。Vercel 也不适合运行需要 Docker、TCP、MQTT 或 Android Emulator 的完整 Runner。

## 14. CLI 常用命令

查看题型：

```powershell
python -m ctf_factory.cli list
```

生成一道题：

```powershell
python -m ctf_factory.cli generate `
  --category crypto `
  --type repeating-xor `
  --difficulty medium `
  --theme "damaged satellite telemetry" `
  --variant qualifier-01
```

批量生成：

```powershell
python -m ctf_factory.cli batch `
  --count 10 `
  --categories web,crypto,forensics,ai-ml `
  --difficulties easy,medium,hard `
  --seed event-2026
```

## 15. 常见问题

### 显示 OFFLINE BRAIN

- 确认 `OPENAI_API_KEY` 是 API Key，不是 ChatGPT 登录状态。
- 重新打开 PowerShell。
- 重启 Studio。
- 确认 API 账户额度和模型权限。

Offline Brain 只影响第一代题面创作，不会关闭构建、Solver、Breaker、变异和记忆。

### 打开题目显示 `{"error":"not found"}`

旧题包可能使用旧运行时。重新从 Studio 生成题目并启动；不要手工猜测容器路径。

### `ERR_CONNECTION_REFUSED`

- 确认 Studio PowerShell 仍在运行。
- 确认 Docker Desktop 已启动。
- 重新点击 **Launch instance**。
- 使用 `docker compose logs` 检查容器。

### Evaluation 很高但题目仍然死板

Evaluation 只能证明已执行的自动检查。它不能代替人类创意与比赛盲测。检查候选的 mechanics、lineage、历史相似度、非预期解和真实选手反馈；对于高水平比赛，仍应由人工出题人修改底层机制并重新进入进化循环。

## 16. 发布前检查清单

- [ ] 22 项自动测试通过
- [ ] 胜出者来自真实构建和执行
- [ ] Solver 连续两次恢复同一 Flag
- [ ] Breaker 没有发现明文泄漏
- [ ] 难度没有被通用解码捷径击穿
- [ ] 运行时入口正常
- [ ] 选手工作台和原生协议正常
- [ ] 人工盲测完成
- [ ] `organizer/` 未进入选手包
- [ ] 生产服务器已配置资源限制、HTTPS 和审计
