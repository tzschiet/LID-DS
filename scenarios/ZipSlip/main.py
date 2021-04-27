import random
import sys
import urllib.request

from lid_ds.core import Scenario, Image, StdinCommand, ExecCommand
from lid_ds.core.collector.json_file_store import JSONFileStorage
from lid_ds.sim import gen_schedule_wait_times
from lid_ds.utils.docker_utils import get_ip_address


class ZipSlip(Scenario):

    def init_victim(self, container, logger):
        print(get_ip_address(container))
        pass

    def wait_for_availability(self, container):
        try:
            victim_url = "http://" + get_ip_address(container) + ":8000/"
            print(f"checking... is victim ready? ({victim_url})")
            with urllib.request.urlopen(victim_url) as response:
                data = response.read().decode("utf8")
                if "READY" in data:
                    print("is ready...")
                    return True
                else:
                    print("not ready yet...")
                    return False
        except Exception as error:
            print("not ready yet with error: " + str(error))
            return False


if __name__ == '__main__':
    warmup_time = int(sys.argv[1])
    recording_time = int(sys.argv[2])
    exploit_time = int(sys.argv[3])

    if exploit_time < 1:
        exploit_time = 0
    else:
        exploit_time = random.randint(int(recording_time * .3), int(recording_time * .8))
    total_duration = warmup_time + recording_time

    min_user_count = 1
    max_user_count = 6
    user_count = random.randint(min_user_count, max_user_count)

    wait_times = [gen_schedule_wait_times(total_duration) for _ in range(user_count)]

    storage_services = [JSONFileStorage()]

    victim = Image("victim_zipslip")
    normal = Image("normal_zipslip", command=StdinCommand(""), init_args="${victim}")
    exploit = Image("exploit_zipslip", command=ExecCommand("python3 /home/exploit.py ${victim}"))

    zipslip_scenario = ZipSlip(
        victim=victim,
        normal=normal,
        exploit=exploit,
        wait_times=wait_times,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services,
        exploit_start_time=exploit_time
    )
    zipslip_scenario()
