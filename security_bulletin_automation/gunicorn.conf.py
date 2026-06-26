import multiprocessing
import os

bind         = f"0.0.0.0:{os.getenv('PORT', '5001')}"
workers      = 1
threads      = multiprocessing.cpu_count() * 2 + 1
worker_class = "gthread"
timeout       = 120
keepalive     = 5
accesslog     = "-"
errorlog      = "-"
loglevel      = "info"
forwarded_allow_ips = "*"
