# CTF Generation AI Agent

一个面向授权比赛和本地教学环境的 AI 辅助 CTF 出题平台。它提供全英文可视化前端，让出题人选择方向、题型、难度和故事背景；AI 负责受约束的题面设计，审核模板负责漏洞行为、附件生成、随机 Flag、Solver 和发布门禁。

> 本项目只应用于本机、比赛基础设施或明确授权的隔离环境。不要用它攻击第三方系统。

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

对 Web、Pwn、AI、Blockchain 和 IoT 题，点击：

```text
Launch instance
```

后端只允许启动 `generated/` 下由平台生成、具有有效 `runtime.json` 的题目，不接受浏览器传入的任意路径或 Shell 命令。

启动后：

- Web/AI：显示并打开 HTTP 地址。
- Pwn：显示 `nc 127.0.0.1 <动态端口>`。
- Blockchain：显示 JSON-RPC 地址。
- IoT：显示 `mosquitto_sub` 命令。
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

## 六、附件题怎么使用

Reverse、Crypto、Forensics 和 Misc 通常不需要常驻服务。生成后使用 `player/` 中的附件完成分析。

Mobile 会生成 APK/Smali/JNI 等逆向材料。若本机已经安装 Android SDK 并创建 AVD，可使用题包中的辅助脚本：

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
├── Dockerfile             # 服务题
├── docker-compose.yml     # 服务题
├── player/                # 选手材料或服务代码
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

测试覆盖：

- 30 个题型 × 3 个难度的生成和 Solver
- 随机 Flag 可恢复性
- 种子可复现性
- Web 攻防回归
- 运行时协议映射
- Docker 实例路径边界
- 选手 ZIP 中的 Flag 和 organizer 泄漏

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
