# CTF Generation AI Agent

一个面向授权比赛和本地教学环境的 AI 辅助 CTF 出题平台。它提供全英文可视化前端，让出题人选择方向、题型、难度和故事背景；AI 负责受约束的题面设计，审核模板负责漏洞行为、附件生成、随机 Flag、Solver 和发布门禁。

> 本项目只应用于本机、比赛基础设施或明确授权的隔离环境。不要用它攻击第三方系统。

## 🏟️ AutoCTF Arena — 让真实队伍上传自己的 AI Agent 来打擂台

**English:** teams upload their own AI agent, it climbs a ladder against its own private
evolving challenge-maker, and the leaderboard ranks every team by how far it actually got.
Full guide: **[ARENA.md](ARENA.md)**.

本仓库不只是出题工具。`arena_platform/` 提供一个完整的比赛平台：每支队伍上传自己的 AI Agent，
与专属的、会进化的出题 Agent 对抗，并按真实战绩排名。

```bash
python -m arena_platform.server --port 8090     # 启动比赛服务器
# 浏览器打开 http://127.0.0.1:8090
```

| 页面 | 作用 |
|---|---|
| `/` | 排行榜、实时阶梯、进行中的比赛 |
| `/submit` | 注册队伍、提交 Agent、开始比赛 |
| `/match/<id>` | 逐级实时观战（SSE 推送）|
| `/docs` | 选手手册：Agent 接口、限制、HTTP API |

比赛规则：

- 出题 Agent 部署 Gen-0；队伍 Agent 交出正确 Flag 后，出题 Agent **进化**成更难的攻击类别，
  并在部署前用 `verify_spec` 实际运行 PoC 验证可解，然后重新部署。
- 队伍 Agent 交不出 Flag、交错 Flag、崩溃或超时，本次攀爬结束。
- **排名先看深度**：实际攻破的最高一级；同级再比总用时，最后比完成时间。

两种参赛方式：

1. **上传代码** —— 一个 `.py` 文件，或包含 `agent.py` 的 `.zip`。在服务器沙箱中运行
   （CPU/内存/进程数硬限制、进程组可终止、环境变量已清理）。网络只保留回环：
   Agent 可以在 `127.0.0.1` 上启动目标程序并攻击它（Web 赛道就是这么解的），
   但流量出不了本机。
2. **远程接口** —— Agent 跑在自己的机器上（Sage、GPU、私有模型），只注册一个 URL，
   平台把题目 POST 过去并读回 Flag。

Agent 接口：

```python
def solve(files, meta=None):
    # files: {"n.txt": "8281...", "e.txt": "3", "c.txt": "5512..."}
    # meta:  {"challenge_id", "gen", "category", "title", "story", "hints"}
    return "flag{...}"      # 解不出来就返回 None
```

先在本地调试，不需要注册也不需要排队：

```bash
python team_agent.py --selftest            # 用真实阶梯本地跑一遍
python team_agent.py --enter --server http://ARENA_HOST:8090 --name "Your Team"
```

公平性保障：每场比赛使用独立随机种子，两支队伍不会拿到相同的模数或相同的 Flag，
因此 Flag 无法互相传递；真实 Flag 只在服务端进程内比对，不会写进事件日志或 API 响应；
Agent 代码也无法 import 本仓库，读不到出题器。

对外开放前请使用 Docker 沙箱：`docker build -t autoctf-arena-agent:latest -f Dockerfile.agent .`
详见 [ARENA.md](ARENA.md)。

## 主要能力

- 10 个 CTF 方向、30 个审核题型、Easy/Medium/Hard 三档难度。
- OpenAI API 或兼容 API 作为可选的 AI 设计大脑。
- 未配置 API Key 时自动使用确定性的 Offline Brain。
- 每次生成随机 Flag，并运行组织者 Solver 验证可解性。
- Web、Pwn、AI、Blockchain、IoT 服务题支持一键 Docker 启停。
- Reverse、Crypto、Forensics、Misc 生成附件型选手包。
- Mobile 生成 Android 逆向附件和本机 AVD 启动辅助。
- 自动生成 `runtime.json`、`deployment.json` 和去除组织者秘密的选手 ZIP。
- Docker 实例只绑定 `127.0.0.1` 的动态端口，避免多个题目互相抢占端口。

## 对抗进化 Agent

Studio 规划题目时会运行两代有界进化循环。评分不再由字段完整性直接推算，而来自临时题包的真实构建和执行结果：

```text
Generator 生成第一代候选
    → 为每个候选构建完整临时题包
    → Solver 连续执行两次并恢复真实 Flag
    → Breaker 检查导出泄漏、通用捷径和运行时完整性
    → 从 SQLite 检索同题型历史 mechanics、指标和失败经验
    → Mutator 根据风险修改编码深度、干扰密度和推理阶段
    → 构建并执行第二代候选
    → Judge 根据执行证据、对抗强度、确定性、新颖度和变异收益选择胜者
    → 所有候选作为脱敏 episode 写入长期记忆
```

经验记忆默认保存在 `.ctf-agent/memory.sqlite3`，该目录已被 Git 忽略。每条 episode 保存题型指纹、lineage、mechanics、执行时间、捷径深度、评分、通过状态和脱敏经验标签；不保存真实 Flag、API Key 或组织者秘密。

查看记忆统计：

```powershell
python -m ctf_factory.cli memory
```

历史检索同时影响新颖度与下一代变异参数：重复的题面/机制会被降分，历史中已经使用过的干扰密度和失败模式会推动 Mutator 选择不同结构。Agent 不允许修改自身源代码，也不能修改或绕过固定安全门禁。

默认第一代生成 3 个候选，随后从较优父代产生 3 个变异候选，共实际构建和执行 6 个题包。在线模型只参与第一代设计，第二代在本地根据执行反馈变异，因此默认每次设计产生 3 次模型调用；Offline Brain 不产生 API 费用。

### 如何使用对抗进化 Agent

1. 启动 Docker Desktop（服务题需要）。
2. 可选执行 `scripts/configure-openai.ps1` 配置在线模型；不配置时使用 Offline Brain。
3. 运行 `python -m ctf_factory.cli studio --port 8787`。
4. 打开 `http://127.0.0.1:8787`。
5. 选择方向、构建原语和难度，填写 Creative Brief。
6. 点击 **Ask AI to create the blueprint**。等待候选题实际构建、Solver 重复执行、Breaker 探测和第二代变异完成。
7. 检查胜出方案的标题、故事、提示和 Designer Notes。
8. 点击 **Build, solve, and audit bundle**，生成胜出方案的正式题包并再次执行发布门禁。
9. 服务题点击 **Launch instance**；附件题使用 `exports/` 中的选手 ZIP。
10. 使用 `python -m ctf_factory.cli memory` 查看累计经验、通过次数和不同题目指纹数量。

前端右上角的 `MEMORY N` 表示已记录的脱敏 episode 数量。Evaluation 面板会显示实际执行、对抗抵抗、确定性、运行时完整性、新颖度、清晰度和变异收益；它不是题目难度或比赛分值。

## 支持的方向与运行方式

| 方向 | 题型 | 交付方式 |
|---|---|---|
| Web | Path Normalization、Weak Session、Query Injection | Docker HTTP |
| Pwn | Stack Overflow Sim、Format String Sim、Integer Overflow Sim | Docker TCP / `nc` |
| AI / LLM | Prompt Injection、RAG Poisoning、Model Extraction | Docker HTTP API |
| Blockchain | Storage Slots、Event Log、Nonce Reuse | Docker JSON-RPC 模拟开发链 |
| IoT | Firmware Strings、UART Fragments、MQTT Retain | Docker MQTT 设备模拟器 |
| Mobile | Android Manifest、DEX Obfuscation、Native Library | Android 逆向附件 / AVD 辅助 |
| Reverse | XOR Strings、Bytecode VM、License Check | 附件 |
| Crypto | Repeating XOR、Weak RSA、LCG Stream | 附件 |
| Forensics | Log Fragments、ZIP Recovery、Packet Timing | 附件 |
| Misc | PPM LSB、Whitespace Code、Encoding Matryoshka | 附件 |

当前 Pwn 题是安全的训练模拟服务，不会提供真实 Shell。Blockchain 使用确定性的 JSON-RPC 开发链模拟器并附带 Solidity 合约材料，不等同于完整 Anvil/EVM。Mobile 模板以逆向分析为主；只有加入经过审核、可构建的 Android 工程模板后，才应自动安装到 Emulator。

## 一、安装准备

需要：

- Windows 10/11、macOS 或 Linux
- Python 3.11 或更高版本
- Docker Desktop（运行服务题时需要）
- Git
- 可选：OpenAI API Key
- 可选：`nc`/Ncat、`mosquitto_sub`、Android SDK、Jadx、Ghidra 等做题工具

克隆并进入项目：

```powershell
git clone https://github.com/yixuan1112-coder/CTF-generation-AI-agent.git
cd CTF-generation-AI-agent
```

建议创建虚拟环境：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

检查环境：

```powershell
python -m ctf_factory.cli doctor
```

## 二、配置 AI API Key

ChatGPT 登录或 ChatGPT Plus 订阅不能直接当作 OpenAI API Key。请在 OpenAI Platform 创建独立 API Key，并确保 API 账户具有可用额度。

Windows 推荐使用项目提供的隐藏输入脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\configure-openai.ps1
```

脚本会为当前 Windows 用户配置：

```text
OPENAI_API_KEY
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-5-mini
```

密钥不会写入前端、项目文件或 Git。配置完成后必须关闭旧终端，并打开一个新的 PowerShell。

也可以只为当前终端设置：

```powershell
$env:OPENAI_API_KEY="your-api-key"
$env:LLM_BASE_URL="https://api.openai.com/v1"
$env:LLM_MODEL="gpt-5-mini"
```

没有 Key 时平台仍然可以生成题目，但前端会显示 `OFFLINE BRAIN`，题面由离线规划器完成。

## 三、打开可视化前端出题

在项目根目录运行：

```powershell
python -m ctf_factory.cli studio --port 8787
```

看到以下内容表示启动成功：

```text
CTF Studio: http://127.0.0.1:8787
```

保持该终端运行，然后浏览器打开：

```text
http://127.0.0.1:8787
```

如果修改了后端代码或 API Key，需要停止旧进程并重新启动：

```powershell
# 在运行 Studio 的终端按 Ctrl+C
python -m ctf_factory.cli studio --port 8787
```

浏览器仍显示旧页面时按 `Ctrl+Shift+R` 强制刷新。

## 四、使用前端生成题目

1. 在 **Choose a challenge domain** 选择题目方向。
2. 选择具体 Challenge Type。
3. 选择 Easy、Medium 或 Hard。
4. 在 Creative Brief 中填写题目背景、目标和希望包含的元素。
5. 点击 **Ask AI to create the blueprint**。
6. 检查 AI 生成的标题、故事、提示和设计备注。
7. 设置 Variant；需要可复现结果时填写 Seed。
8. 点击 **Build, solve, and audit bundle**。
9. 平台生成附件、随机 Flag 和组织者 Solver，并执行发布门禁。
10. 所有门禁通过后显示题目详情。

每次生成都使用不同 Variant 目录，避免覆盖之前的题目。

## 五、本机启动服务题

### 前端一键启动

所有 30 种题型都可以点击：

```text
Launch instance
```

后端只允许启动 `generated/` 下由平台生成、具有有效 `runtime.json` 的题目，不接受浏览器传入的任意路径或 Shell 命令。

启动后会自动打开对应的选手工作台：

- Web：漏洞应用和请求构造器。
- AI：聊天界面、模型攻击目标和 Flag 提交。
- Pwn：证据预览和网页终端，同时保留 `nc 127.0.0.1 <动态端口>`。
- Blockchain：合约证据和 RPC 控制台，同时保留 JSON-RPC 接口。
- IoT：设备证据和消息控制台，同时保留 `mosquitto_sub` 接口。
- Reverse、Crypto、Forensics、Misc：附件下载、文本或 Hex 预览和 Flag 提交。
- Mobile：APK/Smali/JNI 证据工作台；仍可配合 Android Emulator、Jadx、apktool 或 Ghidra。
- 点击 **Stop instance** 停止并清理该题容器。

### 手动启动

也可以进入题目目录：

```powershell
cd generated\<challenge-slug>
docker compose up -d --build
docker compose ps
```

查看日志：

```powershell
docker compose logs -f
```

停止题目：

```powershell
docker compose down
```

## 六、附件与 Mobile 题怎么使用

Reverse、Crypto、Forensics、Misc 和 Mobile 现在同样提供浏览器工作台。工作台不会替代真实附件：选手可以在线预览、下载原始文件，再使用对应专业工具分析。

Mobile 会生成 APK/Smali/JNI 等逆向材料。若本机已经安装 Android SDK 并创建 AVD，仍可使用题包中的辅助脚本：

```powershell
powershell -File .\launch-android.ps1 -Avd <AVD名称>
```

现有 Mobile 题主要使用 Jadx、apktool、Ghidra 等工具分析，并不保证所有合成附件都是可安装的生产 APK。

## 七、题包结构

```text
generated/<challenge-slug>/
├── README.md              # 公开题面
├── challenge.json         # 公开元数据，不含 Flag
├── quality.json           # 质量门禁结果
├── runtime.json           # 本机实例运行协议
├── deployment.json        # 上线交付描述
├── Dockerfile             # 隔离的选手工作台/服务
├── docker-compose.yml     # 本地端口和容器安全配置
├── player/                # 选手材料、工作台或服务代码
└── organizer/
    ├── spec.json          # 完整规格和真实 Flag，必须保密
    └── solver.py          # 官方自动 Solver
```

绝对不要把 `organizer/` 发给选手，也不要把完整 `generated/` 目录放到公开对象存储。

## 八、导出选手包

前端生成完成时会自动在 `exports/` 创建选手 ZIP。也可以手动执行：

```powershell
python -m ctf_factory.cli export generated\<challenge-slug>
```

导出器会：

- 排除 `organizer/`
- 排除组织者完整规格和 Solver
- 对服务题重新渲染公开包
- 将真实 Flag 替换为 `flag{replace_at_deployment}`
- 保留题面、公开附件和部署所需文件

上线时必须区分：

- **私有部署题包**：组织者部署到服务器，包含该实例真实 Flag。
- **公开选手 ZIP**：上传给选手，不能包含比赛真实 Flag。

## 九、把一道题上线到比赛平台

### 方式 A：附件题上线

适合 Reverse、Crypto、Forensics、Misc 和多数 Mobile 题。

1. 生成并审核题目。
2. 运行组织者 Solver，确认能够恢复真实 Flag。
3. 导出选手 ZIP。
4. 把 ZIP 上传到 CTFd、S3、Cloudflare R2 或 OSS。
5. 在 CTFd 创建题目，填写标题、题面、分类、分值和 Flag。
6. 将选手 ZIP 作为附件或对象存储下载链接。
7. 下载公开附件并再次扫描，确认没有 `organizer/` 和真实 Flag。

### 方式 B：服务题上线

适合 Web、Pwn、AI API、Blockchain RPC 和 IoT MQTT。

1. 准备一台隔离的 Linux Docker 主机或独立 Runner。
2. 将完整生成题包通过 SSH/CI 私下复制到服务器。
3. 不要把私有部署题包上传到公开 GitHub 或公开对象存储。
4. 在服务器进入题目目录并构建：

```bash
docker compose up -d --build
docker compose ps
```

5. 本项目默认把端口动态绑定到 `127.0.0.1`。正式上线时通过反向代理、TCP 负载均衡或比赛平台 Runner 暴露服务。
6. Web、AI API、Blockchain RPC 应通过 Nginx/Caddy/Traefik 配置 HTTPS。
7. Pwn TCP 和 MQTT 使用独立端口、连接数限制、速率限制和超时。
8. 在 CTFd 题面中填写公开 URL、`nc host port`、RPC 地址或 MQTT 命令。
9. 使用非组织者账户从公网完成一次完整解题测试。
10. 比赛结束后执行 `docker compose down` 并销毁题目实例。

### 多队伍独立实例

正式比赛不应让所有队伍共用可修改状态。推荐：

```text
CTFd / Frontend
        |
        v
Authenticated API
        |
        v
Redis Task Queue
        |
        v
Isolated Docker Runner
        |
        +-- Team A instance
        +-- Team B instance
        +-- Team C instance
```

每个实例需要：

- 独立 Compose project name
- 独立随机端口和 Flag
- CPU、内存、PID、磁盘和运行时间限制
- 默认禁止访问互联网和宿主机
- 到期自动销毁
- 启停、用户、IP、题目和异常操作审计日志

当前仓库已完成题目运行时、动态端口和本机生命周期管理。若要把 Studio 本身公开给多用户，还需要 FastAPI 登录权限、PostgreSQL、Redis、对象存储、独立 Runner、HTTPS、限额和审计控制层。不要直接把 `127.0.0.1:8787` 的本机 Studio 暴露到互联网。

更多生产部署注意事项参见 [DEPLOYMENT.md](DEPLOYMENT.md)。

## 十、命令行使用

列出题型：

```powershell
python -m ctf_factory.cli list
```

生成单题：

```powershell
python -m ctf_factory.cli generate `
  --category web `
  --type weak-session `
  --difficulty medium `
  --theme "Lunar identity archive" `
  --variant event-01 `
  --output generated
```

批量生成：

```powershell
python -m ctf_factory.cli batch `
  --count 10 `
  --categories web,crypto,forensics,ai-ml `
  --difficulties easy,medium,hard `
  --theme "Autonomous cyber range" `
  --seed event-2026
```

运行 Web 攻防裁判：

```powershell
python -m ctf_factory.cli arena generated\web-query-injection-hard
```

## 十一、测试

运行全部测试：

```powershell
python -m unittest discover -s tests -v
```

只运行比赛平台的测试：

```powershell
python -m unittest tests.test_arena -v
```

测试覆盖：

- 30 个题型 × 3 个难度的生成和 Solver
- 随机 Flag 可恢复性
- 种子可复现性
- Web 攻防回归
- 运行时协议映射
- Docker 实例路径边界
- 选手 ZIP 中的 Flag 和 organizer 泄漏
- 比赛平台：Agent 沙箱隔离、上传校验、排名顺序、并发领取、Flag 不泄漏、API 鉴权

## 十二、常见问题

### 前端显示 OFFLINE BRAIN

Studio 启动时没有读取到 `OPENAI_API_KEY`。确认密钥已配置，并在新的终端中重新启动 Studio。

### `127.0.0.1:8787` 拒绝连接

Studio 进程没有运行。重新执行：

```powershell
python -m ctf_factory.cli studio --port 8787
```

### 点击 Launch instance 后 Docker 报错

确认 Docker Desktop 已启动：

```powershell
docker info
python -m ctf_factory.cli doctor
```

### 题目地址不是 8000

这是正常行为。平台为每个实例分配动态本机端口，避免多个题目冲突。使用前端返回的地址或命令。

### 修改代码后网页没有变化

停止并重启 Studio，然后按 `Ctrl+Shift+R` 强制刷新浏览器。

## 安全边界

- 只生成 allow-list 中经过审核的题型。
- AI 不直接生成未经审核的漏洞执行代码。
- Studio 只接受 localhost 请求。
- 实例管理只解析生成的 challenge ID，不接受任意目录或命令。
- Docker 默认只绑定 `127.0.0.1`，使用只读文件系统、丢弃 Linux capabilities，并启用 `no-new-privileges`。
- 不挂载 Docker Socket、宿主机目录或真实凭据。
- API Key 只能放在服务端环境变量，不能写入前端或提交到 Git。
- `organizer/`、真实 Flag 和私有部署包必须保持私密。
