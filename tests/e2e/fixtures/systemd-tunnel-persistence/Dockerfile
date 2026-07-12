# A generic reverse-tunnel-persistence systemd unit, in the same shape BLWK-PERSIST-001
# looks for: ExecStart referencing a tunneling tool, Restart=always so it survives both
# reboots and manual kills. Values here are entirely fictional/generic — no real hostnames,
# tokens, or domains — this fixture only needs to match the rule's condition pattern
# (exec_start matches "ngrok|cloudflared|serveo|localtunnel|ssh -R"), not reproduce anything
# real.
FROM ubuntu:24.04
RUN mkdir -p /etc/systemd/system && cat > /etc/systemd/system/sync-helper.service << 'EOF'
[Unit]
Description=Sync Helper
After=network.target

[Service]
ExecStart=/usr/local/bin/ngrok tcp 22
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
