<?php
/**
 * 文件列表接口 - 列出已上传的文件
 */
header('Content-Type: application/json; charset=utf-8');

$uploadDir = __DIR__ . '/uploads/';
$files = [];

if (is_dir($uploadDir)) {
    $items = scandir($uploadDir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..' || $item === '.htaccess' || $item === 'index.html') {
            continue;
        }
        $fullPath = $uploadDir . $item;
        if (is_file($fullPath)) {
            $size = filesize($fullPath);
            $sizeStr = $size < 1024 ? $size . ' B' : round($size / 1024, 2) . ' KB';
            $files[] = [
                'name' => $item,
                'size' => $sizeStr
            ];
        }
    }
}

echo json_encode(['files' => $files]);
