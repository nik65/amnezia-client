#!/bin/bash

APP_NAME=AmneziaVPN
LOG_FOLDER=/var/log/$APP_NAME
LOG_FILE="$LOG_FOLDER/post-install.log"
APP_PATH=/opt/$APP_NAME

# Preserve best-effort desktop/log cleanup, but propagate failures of the
# service installation to the installer's Execute operation. Do not exit early:
# SteamOS read-only mode must still be restored after an installation failure.
INSTALL_STATUS=0
run_required() {
        "$@"
        local result=$?
        if [ "$result" -ne 0 ]; then
                INSTALL_STATUS=1
                echo "Required installation command failed ($result): $*" >&2
        fi
        return 0
}

if ! test -f $LOG_FOLDER; then
        sudo mkdir $LOG_FOLDER
        echo "AmneziaVPN log dir created at /var/log/"
fi

if ! test -f $LOG_FILE; then
        touch $LOG_FILE
        echo "AmneziaVPN log file created at /var/log/AmneziaVPN/post-install.log"
fi

date > $LOG_FILE
echo "Script started" >> $LOG_FILE
sudo killall -9 $APP_NAME 2>> $LOG_FILE

if command -v steamos-readonly &> /dev/null; then
        run_required sudo steamos-readonly disable >> $LOG_FILE
        echo "steamos-readonly disabled" >> $LOG_FILE
fi

if sudo systemctl is-active --quiet $APP_NAME; then
	run_required sudo systemctl stop $APP_NAME >> $LOG_FILE
	sudo systemctl disable $APP_NAME >> $LOG_FILE
	sudo rm -rf /etc/systemd/system/$APP_NAME.service >> $LOG_FILE
fi

run_required sudo chmod -R a-w $APP_PATH/

run_required sudo cp $APP_PATH/$APP_NAME.service /etc/systemd/system/ >> $LOG_FILE

run_required sudo systemctl start $APP_NAME >> $LOG_FILE
run_required sudo systemctl enable $APP_NAME >> $LOG_FILE
sudo ln -sf $APP_PATH/bin/$APP_NAME /usr/local/sbin/$APP_NAME >> $LOG_FILE
sudo ln -sf $APP_PATH/bin/$APP_NAME /usr/local/bin/$APP_NAME >> $LOG_FILE

echo "user desktop creation loop started" >> $LOG_FILE
sudo cp $APP_PATH/$APP_NAME.desktop /usr/share/applications/ >> $LOG_FILE
sudo cp $APP_PATH/$APP_NAME.png /usr/share/pixmaps/ >> $LOG_FILE
sudo chmod 555 /usr/share/applications/$APP_NAME.desktop >> $LOG_FILE

echo "user desktop creation loop ended" >> $LOG_FILE

if command -v steamos-readonly &> /dev/null; then
        run_required sudo steamos-readonly enable >> $LOG_FILE
        echo "steamos-readonly enabled" >> $LOG_FILE
fi

date >> $LOG_FILE
echo "Service status:" >> $LOG_FILE
sudo systemctl status $APP_NAME >> $LOG_FILE
date >> $LOG_FILE
echo "Script finished" >> $LOG_FILE
exit "$INSTALL_STATUS"
