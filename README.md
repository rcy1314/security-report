# 安全事件报告（溯源/应急复盘）

- **报告日期**：2025-12-22
- **对象**：本站（WordPress + Nginx + PHP-FPM，疑似宝塔面板环境）
- **事件类型**：服务器被植入恶意二进制（伪装为 `43.zip`），疑似挖矿/僵尸网络载荷；存在持久化/投递链路风险
- **结论等级**：高（已出现恶意进程运行 + 对外联通）

![1766376817261](https://s2.loli.net/2025/12/22/pPiVMrXTEd53Asa.png)

## 1. 摘要（Executive Summary）

在服务器上发现异常高 CPU 占用，定位到两个同名进程 `43.zip`（以 `www` 用户运行），并与外部地址 **`服务器IP:110`** 建立 TCP 连接。该“`43.zip`”并非压缩包，而是 **x86_64 ELF 可执行文件**（静态链接、去符号），属于典型恶意程序伪装方式。

同时，在服务器 `root` 计划任务中发现 `/root/.httpsok/httpsok.sh` 定时执行项。该脚本包含 **远程下载并执行**（`curl ... > binary && chmod +x` / `curl ... | bash`）的高风险逻辑。虽然其域名指向 `httpsok.com`/`get.httpsok.com`（看似官方），但在“已被入侵”前提下，它构成潜在的投递/复活触发点，应当停用并隔离。

此外，Nginx/PHP 相关日志出现大量 WordPress 路径枚举、插件探测、REST API 探测与自定义 token 接口调用，表明站点持续遭受扫描与潜在爆破。

---

## 2. 关键证据（Evidence）

### 2.1 异常进程（CPU Top）

- **进程名**：`43.zip`
- **运行用户**：`www`
- **PID**：7852、7593（曾同时存在）
- **CPU/内存**：单进程约 `138% CPU`、`29.9% MEM`（多核占用）
- **命令行**：
  - `./43.zip -o 服务器IP:110 -B`
- **网络连接**：
  - `ESTAB <server_ip>:<ephemeral_port> -> 服务器IP:110`（后续终止后出现过 FIN-WAIT 状态，最终消失）

### 2.2 恶意文件落地点（服务器侧）

根据 `/proc/<pid>/exe`：

- `/www/.Recycle_bin/_bt_www_bt_wwwroot_bt_noisevip.cn_bt_43.zip_t_1766373625.9903157`
- `/www/.Recycle_bin/_bt_www_bt_wwwroot_bt_noisevip.cn_bt_wp-content_t_1766373839.333882/plugins/zjboe/43.zip`

> 说明：路径含 `_bt_`、`.Recycle_bin` 特征，疑似宝塔环境回收/历史目录被用于隐藏投递文件。

### 2.3 本地下载样本鉴定

对本地文件

- **file(1) 识别**：
  - `ELF 64-bit LSB executable, x86-64, statically linked, stripped`
- **大小**：`8,334,576` bytes
- **魔数（前 16 字节）**：`7f454c46020101000000000000000000`（ELF）

哈希（用于威胁情报检索/留证）：

- **MD5**：`72a37a2fa588e013eafd695b8b5b0e61`
- **SHA1**：`53cfa587d5cfd7e5e193fc0b1a1575b2b0fefd33`
- **SHA256**：`0c748b9e8bc6b5b4fe989df67655f3301d28ef81617b9cbe8e0f6a19d4f9b657`
- **ELF BuildID (sha1)**：`ad34d49df4171e0ae93aa6d8d91e54679714eb2e`

### 2.4 可疑持久化/投递点：`httpsok.sh` 计划任务

- **路径**：`/root/.httpsok/httpsok.sh`
- **cron（root）**：曾存在定时执行（后续已注释停用）
- **脚本中高风险行为**（用户 grep 输出）：
  - `SCRIPT_URL="https://get.httpsok.com/"`
  - `curl -s "$SCRIPT_URL" > "$PROJECT_ENTRY_BIN" && chmod +x ...`
  - `curl -s $SCRIPT_URL | bash -s ...`

> 说明：即便域名看似官方，该行为在“已入侵”机器上属于高风险执行链路，需停用并隔离以避免复活/二次投递。

### 2.5 Web 层扫描/探测迹象（日志）

在 `noisevip.cn_error_2025-12-22_000102.log` 中观测到：

- 大量请求触发 `directory index ... is forbidden` 的 WordPress 目录枚举
  - `/wp-admin/css/`、`/wp-admin/js/`、`/wp-includes/.../`、`/wp-content/.../`
- 插件/备份目录探测
  - `/wp-content/backups-dup-lite`、`/wp-content/plugins/.../readme.txt`
- REST API 探测
  - `/wp-json/wp/v2/posts?...`
- 自定义 token 接口调用（疑似爆破/撞库，且将密码置于 query）
  - `POST /wp-json/jijianyun/v1/token?username=...&password=...`

### 2.6 站点自身异常噪音（需修复）

- `PHP Warning: Constant WP_USE_THEMES already defined in /www/wwwroot/noisevip.cn/index.php on line 2`

该问题会导致日志大量刷屏，影响溯源与告警准确性。

---

## 3. 事件时间线（Timeline）

> 注：精确时间以服务器日志/审计日志为准，此处为已确认事实的相对顺序。

1. 发现服务器负载/CPU 100%，站点运行堵塞。
2. `ps` 定位 Top 进程为 `43.zip`（两个实例），用户为 `www`。
3. 通过 `/proc/<pid>/exe` 与 `/proc/<pid>/cmdline` 确认外联参数 `-o 服务器IP:110 -B`。
4. `ss -antp` 观察到与 `服务器IP:110` 的 TCP `ESTAB`。
5. 发现 `43.zip` 落地于 `/www/.Recycle_bin/...` 及 `wp-content/plugins/zjboe/` 相关路径。
6. 通过 grep 定位 `/root/.httpsok/httpsok.sh` 含远程下载执行逻辑，且 root crontab 存在定时执行项。
7. 终止异常进程后，连接进入 `FIN-WAIT` 并最终消失。
8. 将 root crontab 中 `httpsok.sh` 任务注释停用。
9. 将 `43.zip` 下载到 mac 本地，确认为 ELF 可执行文件（非 zip）。

---

## 4. IOC（Indicators of Compromise）

### 4.1 外联地址

- **IP**：`服务器IP`
- **Port**：`110/tcp`

### 4.2 进程/命令

- `43.zip`
- `./43.zip -o 服务器IP:110 -B`

### 4.3 文件路径（服务器）

- `/www/.Recycle_bin/_bt_www_bt_wwwroot_bt_noisevip.cn_bt_43.zip_t_1766373625.9903157`
- `/www/.Recycle_bin/_bt_www_bt_wwwroot_bt_noisevip.cn_bt_wp-content_t_1766373839.333882/plugins/zjboe/43.zip`
- `/root/.httpsok/httpsok.sh`
- `/root/.httpsok/httpsok.log`

### 4.4 样本哈希

- `SHA256 0c748b9e8bc6b5b4fe989df67655f3301d28ef81617b9cbe8e0f6a19d4f9b657`
- `MD5    72a37a2fa588e013eafd695b8b5b0e61`

---

## 5. 初步溯源判断（Root Cause Hypothesis）

基于当前证据，较高概率的入侵链路（从高到低）：

1. **WordPress 插件/主题/上传目录被写入**（高概率）
   - 恶意样本路径直接落在 `wp-content/plugins/...` 相关历史/回收路径中。
   - 日志显示存在持续的 WP 目录枚举、插件探测、备份目录探测。

2. **弱口令/接口爆破导致的后台或 API token 获取**（中高概率）
   - `POST /wp-json/jijianyun/v1/token?username=...&password=...` 出现，形态像撞库/爆破。
   - 若该接口与登录/鉴权相关，可能被用于获取授权后上传/执行。

3. **宝塔面板/服务器管理面板暴露与被入侵**（中概率）
   - `.Recycle_bin/_bt_...`  等结构符合 BT 环境。
   - BT/面板被入侵后，攻击者可写入网站目录并启动进程。

4. **`httpsok.sh` 作为投递器被滥用/链路被劫持**（中概率）
   - 当前看到 `SCRIPT_URL` 指向 `get.httpsok.com`（看似官方），不排除脚本被篡改或执行参数被注入。
   - 即便未被篡改，在已入侵环境中也会扩大攻击面。

> 当前证据能证明“已执行恶意程序并外联”，但尚不足以精确还原“首次入侵点”。需要补充 Web/SSH/面板日志与文件时间线。

---

## 6. 已采取处置（Containment/Eradication）

- 识别并终止 `43.zip` 异常进程（避免继续占用 CPU 与对外联通）。
- 确认外联 `服务器IP:110` 连接最终消失。
- root crontab 中 `httpsok.sh` 任务已注释停用（防止定时触发下载执行逻辑）。
- `httpsok.sh` 已执行 `chmod 000` 降低误执行风险。
- 将样本下载到本地并完成文件类型与哈希留证。

---

## 7. 已采取的行动

1. **阻断 IOC 外联**（服务器防火墙/安全组）：
   - 阻断 `服务器IP:110/tcp`（以及该 IP 全部出站连接更稳妥）。
2. **全面排查复活点**：
   - `crontab -l`、`crontab -u www -l`
   - `/etc/cron.*`、`/var/spool/cron/`
   - `systemctl list-unit-files`、`systemctl list-units --state=running`
3. **站点目录最近变更扫描**（重点）：
   - `wp-content/plugins/`
   - `wp-content/themes/`
   - `wp-content/uploads/`
4. **修复 `WP_USE_THEMES already defined`**：减少日志噪音，便于发现真实攻击痕迹。

### 7.2 

1. **WAF/Fail2ban**：
   - 对 WP 扫描路径、插件 readme 探测、备份目录探测实施封禁/限速。

### 7.3 

- 开启并留存 Nginx access log、PHP-FPM log、SSH 登录审计。

---

## 8. 已留存的补充材料（用于精确溯源）

1. **Nginx access log**（与恶意进程出现时段重叠的 1~3 小时）：
   - 重点过滤：`wp-admin`、`wp-login.php`、`wp-json`、`uploads`、`admin-ajax.php`、可疑 `.php`。
2. **SSH 日志**：
   - `/var/log/auth.log` 或 `/var/log/secure`
3. **文件时间线**：
   - `find /www/wwwroot/noisevip.cn -type f -mtime -7 -ls`
4. **计划任务与 systemd**：
   - `crontab -l; crontab -u www -l`
   - `systemctl list-unit-files; systemctl list-units --type=service --state=running`
5. **宝塔面板日志/操作记录**（若存在）：
   - 面板登录 IP、执行记录、任务变更记录。

---

## 9. 附录：

- **SHA256**：
  - `0c748b9e8bc6b5b4fe989df67655f3301d28ef81617b9cbe8e0f6a19d4f9b657`

---

> 本报告已留存截图证据及ip来访记录，会进一步溯源
