import os
import commands
import signal


NAT_SCRIPT_NAME = "dummynat.py"


def start_imitator_nat(natype):
    os.system("python /root/%s %s" % (NAT_SCRIPT_NAME, str(natype)))


def get_imitator_pid():
    result = commands.getoutput("ps aux | grep python | grep %s | grep -v grep | awk '{print $2}'" % NAT_SCRIPT_NAME)
    return result


def stop_imitator_nat():
    pid = get_imitator_pid()
    pids = pid.split("\n")
    for p_id in pids:
        if p_id.isdigit():
            os.kill(int(p_id), signal.SIGTSTP)


if __name__ == "__main__":
    stop_imitator_nat()
