#!/bin/bash



SERVICE_NAME="account-monitor"

INSTALL_DIR="/data/scripts/account_monitor"

PYTHON_EXEC=$(which python3)

LOG_FILE="/data/scripts/account_monitor/account_monitor.log"

ERR_FILE="/data/scripts/account_monitor/account_monitor.err"

SYSTEMD_PATH="/etc/systemd/system/${SERVICE_NAME}.service"



echo "✅ 开始安装 Account Monitor..."

echo "✅ 執行之前先請手動設定好代理 proxy，需要能上網安裝套件等。"



# Step 0: 安装 Python 依赖

pip3 install mysql-connector-python

pip3 install pyyaml

pip3 install requests



# Step 1: 创建工作目录

mkdir -p "$INSTALL_DIR"



# Step 2: 拷贝脚本和配置

echo "📁 拷贝监控脚本与配置..."

cp account_monitor.py "$INSTALL_DIR/" || { echo "❌ 缺少 account_monitor.py"; exit 1; }

cp .account_monitor.yml "$INSTALL_DIR/" || { echo "❌ 缺少 .account_monitor.yml，请先参考 .account_monitor.yml.example 创建配置文件"; exit 1; }



# Step 3: 创建日志文件

touch "$LOG_FILE" "$ERR_FILE"

chmod 666 "$LOG_FILE" "$ERR_FILE"



# Step 4: 创建 systemd 服务文件

echo "⚙️ 创建 systemd 服务文件..."

cat > "$SYSTEMD_PATH" <<EOF

[Unit]

Description=MySQL/TiDB Account Monitor Daemon

After=network.target



[Service]

Type=simple

User=root

WorkingDirectory=${INSTALL_DIR}

ExecStart=${PYTHON_EXEC} ${INSTALL_DIR}/account_monitor.py

Restart=always

RestartSec=5

StandardOutput=append:${LOG_FILE}

StandardError=append:${ERR_FILE}



[Install]

WantedBy=multi-user.target

EOF



# Step 5: 重新加载 systemd、启用服务

echo "🚀 启动服务并设置为开机自启..."

systemctl daemon-reexec

systemctl daemon-reload

systemctl enable "$SERVICE_NAME"

systemctl restart "$SERVICE_NAME"



# Step 6: 状态输出

sleep 1

systemctl status "$SERVICE_NAME" --no-pager



echo "✅ 安装完成！日志路径："

echo " 📄 $LOG_FILE"

echo " ❗ $ERR_FILE"

echo ""

echo "常用命令："

echo " systemctl status $SERVICE_NAME    # 查看状态"

echo " systemctl stop $SERVICE_NAME      # 停止"

echo " systemctl restart $SERVICE_NAME   # 重启"

echo " journalctl -u $SERVICE_NAME -f    # 查看实时日志"
