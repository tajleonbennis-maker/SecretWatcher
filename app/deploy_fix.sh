#!/bin/bash
# SecretWatcher 误报过滤修复 - 自包含部署脚本
# 自动从 GitHub 拉取最新代码并执行清理

set -e

echo "=========================================="
echo "SecretWatcher 误报过滤修复 - 自动部署"
echo "=========================================="
echo "时间: $(date)"
echo ""

# 配置
DEPLOY_DIR="/opt/secretwatcher/current"
DB_PATH="/var/lib/secretwatcher/secretwatcher.db"
BACKUP_DIR="/opt/secretwatcher/backups/$(date +%Y%m%d_%H%M%S)"
SERVICE_NAME="secretwatcher"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}错误: 请使用 root 用户执行此脚本${NC}"
    exit 1
fi

# Step 1: 备份
echo -e "${YELLOW}[1/5] 备份当前版本...${NC}"
mkdir -p "$BACKUP_DIR"
cp -r "$DEPLOY_DIR/app/credentials.py" "$BACKUP_DIR/" 2>/dev/null || true
cp "$DB_PATH" "$BACKUP_DIR/" 2>/dev/null || true
echo -e "${GREEN}✓ 备份完成: $BACKUP_DIR${NC}"

# Step 2: 更新代码
echo -e "${YELLOW}[2/5] 从 GitHub 拉取最新代码...${NC}"
cd "$DEPLOY_DIR"

# 备份当前 credentials.py 以防万一
cp app/credentials.py app/credentials.py.pre-fix 2>/dev/null || true

# 尝试 git pull
if git fetch origin main 2>&1; then
    git reset --hard origin/main
    echo -e "${GREEN}✓ 代码已更新 (git)${NC}"
else
    echo -e "${YELLOW}⚠ git fetch 失败，尝试直接下载...${NC}"
    curl -sL "https://raw.githubusercontent.com/tajleonbennis-maker/SecretWatcher/main/app/credentials.py" \
        -o app/credentials.py.new
    
    if [ -f "app/credentials.py.new" ] && [ -s "app/credentials.py.new" ]; then
        mv app/credentials.py.new app/credentials.py
        echo -e "${GREEN}✓ 已通过 curl 下载最新代码${NC}"
    else
        echo -e "${RED}✗ 下载失败${NC}"
        exit 1
    fi
fi

# Step 3: 执行数据清理
echo -e "${YELLOW}[3/5] 清理历史误报数据...${NC}"

sqlite3 "$DB_PATH" << 'SQL_EOF'
-- 标记 LibreChat 前端代码误报
UPDATE credential_findings
SET status = 'false_positive',
    reviewed_at = datetime('now'),
    review_reason = 'LibreChat前端代码误报'
WHERE product LIKE '%LibreChat%'
  AND (source_path LIKE '%.js' OR source_path LIKE '%.mjs' OR source_path LIKE '%.map')
  AND (model_names IS NULL OR model_names = '' OR model_names LIKE '%未识别%');

-- 标记 Open WebUI 示例值
UPDATE credential_findings
SET status = 'false_positive',
    reviewed_at = datetime('now'),
    review_reason = '疑似示例值wxyz'
WHERE key_suffix8 = 'wxyzwxyz' OR key_suffix8 LIKE '%wxyz%';

UPDATE credential_findings
SET status = 'false_positive',
    reviewed_at = datetime('now'),
    review_reason = '疑似示例值后缀'
WHERE key_suffix8 IN ('b13ab13a', '89+/89+/', 'c592c592', 'jFv+jFv+', 'anceance', 'bb56bb56');

-- 标记高频出现
CREATE TEMP TABLE IF NOT EXISTS suffix_freq AS
SELECT asset_name, key_suffix8, COUNT(*) as cnt
FROM credential_findings
WHERE status IS NULL OR status = 'pending_review'
GROUP BY asset_name, key_suffix8
HAVING cnt >= 5;

UPDATE credential_findings
SET status = 'suspicious',
    reviewed_at = datetime('now'),
    review_reason = '同资产高频出现(>=5次)'
WHERE (asset_name, key_suffix8) IN (SELECT asset_name, key_suffix8 FROM suffix_freq)
  AND (status IS NULL OR status = 'pending_review');

DROP TABLE IF EXISTS suffix_freq;

-- 标记低置信度未识别模型
UPDATE credential_findings
SET status = 'suspicious',
    reviewed_at = datetime('now'),
    review_reason = '低置信度未识别模型'
WHERE (model_names IS NULL OR model_names = '' OR model_names LIKE '%未识别%')
  AND confidence < 0.8
  AND (status IS NULL OR status = 'pending_review');
SQL_EOF

echo -e "${GREEN}✓ 数据清理完成${NC}"

# Step 4: 重启服务
echo -e "${YELLOW}[4/5] 重启服务...${NC}"
systemctl restart "$SERVICE_NAME"
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${GREEN}✓ 服务运行正常${NC}"
else
    echo -e "${RED}⚠ 服务启动异常，查看日志: journalctl -u $SERVICE_NAME -n 50${NC}"
fi

# Step 5: 显示结果
echo ""
echo -e "${YELLOW}[5/5] 部署结果统计:${NC}"
echo ""

sqlite3 "$DB_PATH" "SELECT 
  '总发现数: ' || COUNT(*) || CHAR(10) ||
  '  待复核: ' || SUM(CASE WHEN (status IS NULL OR status='pending_review') THEN 1 ELSE 0 END) || CHAR(10) ||
  '  误报(已标记): ' || SUM(CASE WHEN status='false_positive' THEN 1 ELSE 0 END) || CHAR(10) ||
  '  可疑: ' || SUM(CASE WHEN status='suspicious' THEN 1 ELSE 0 END) as summary
FROM credential_findings;"

echo ""
echo "=========================================="
echo -e "${GREEN}✅ 部署完成！${NC}"
echo ""
echo "备份位置: $BACKUP_DIR"
echo "Git Commit: fcd01cbe0ea688b0cc2d4f76062eec30cce9dacd"
echo ""
echo "回滚命令:"
echo "  cp $BACKUP_DIR/credentials.py $DEPLOY_DIR/app/credentials.py"
echo "  cp $BACKUP_DIR/secretwatcher.db $DB_PATH"
echo "  systemctl restart $SERVICE_NAME"
echo "=========================================="
