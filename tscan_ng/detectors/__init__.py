from tscan_ng.detectors import http_basic, ftp, pop3, imap, smtp

DETECTORS = [
    http_basic.detect,
    ftp.detect,
    pop3.detect,
    imap.detect,
    smtp.detect,
]
