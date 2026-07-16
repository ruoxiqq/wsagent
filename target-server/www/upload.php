<?php
/**
 * 漏洞文件上传接口
 * 
 * 安全警告：此文件存在严重的文件上传漏洞！
 * 不检查文件类型、不检查文件内容、不重命名文件、上传目录可执行脚本。
 * 仅供安全教学演示使用，严禁用于非授权场景。
 */

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['status' => 'error', 'message' => '请使用 POST 方法上传']);
    exit;
}

if (!isset($_FILES['fileToUpload']) || $_FILES['fileToUpload']['error'] !== UPLOAD_ERR_OK) {
    echo json_encode(['status' => 'error', 'message' => '未接收到文件或上传出错']);
    exit;
}

$file = $_FILES['fileToUpload'];
$uploadDir = __DIR__ . '/uploads/';

// 确保上传目录存在
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

// 漏洞点1: 直接使用原始文件名，不做任何过滤
$filename = $file['name'];

// 漏洞点2: 不检查文件扩展名，允许 .php 等可执行文件上传
// 漏洞点3: 不检查 MIME 类型
// 漏洞点4: 不检查文件内容是否包含恶意代码

$targetPath = $uploadDir . $filename;

// 漏洞点5: 直接移动文件到可被 Web 访问且可执行的目录
if (move_uploaded_file($file['tmp_name'], $targetPath)) {
    // 设置文件权限使其可执行
    chmod($targetPath, 0644);

    echo json_encode([
        'status'   => 'success',
        'message'  => '文件上传成功',
        'path'     => 'uploads/' . $filename,
        'filename' => $filename,
        'size'     => $file['size']
    ]);
} else {
    echo json_encode(['status' => 'error', 'message' => '文件保存失败']);
}
