until docker ps --format "{{.Names}}" | grep -q "bl-pf-trace_e3-s3"; do sleep 60; done; touch /root/bl/stop_trace
