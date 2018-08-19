import ipaddress
import multiprocessing
import os
import signal
import sys

from dns_request_sender    import DNSRequestSender
from dns_response_listener import DNSResponseListener

class Manager(object):

    def __init__(self, start, end, number_of_workers):
        self.__ip_segments    = self.__assign_jobs(start, end, number_of_workers)
        self.__workers        = []
        self.__worker_process = []

        for index in range(len(self.__ip_segments)-1):
            self.__workers.append(
                DNSRequestSender(
                    self.__ip_segments[index],
                    self.__ip_segments[index+1],
                    index
                )
            )
        
        for worker in self.__workers:
            self.__worker_process.append(
                multiprocessing.Process(
                    target=worker.run
                )
            )

        self.__listener = DNSResponseListener()
        self.__listener_process = multiprocessing.Process(
            target=self.__listener.run
            )

    def __assign_jobs(self, start, end, workers) -> [int]:
        step_length = (end - start + 1) // workers
        remaining   = (end - start + 1) % workers
        breakpoints = [start,]
        
        while len(breakpoints) < workers + 1:

            if len(breakpoints) <= remaining:
                next_point = breakpoints[-1] + step_length + 1
            else:
                next_point = breakpoints[-1] + step_length
            breakpoints.append(next_point)

        return breakpoints

    def run(self):
        self.__listener_process.start()
        print("Listener is on at PID {}".format(self.__listener_process.pid))
        for process_index in range(len(self.__worker_process)):
            self.__worker_process[process_index].start()
            print(self.__workers[process_index])

    def __del__(self):
        for process_index in range(len(self.__worker_process)):
            try:
                process_id = self.__worker_process[process_index].pid
                if process_id:
                    os.kill(process_id, signal.SIGINT)
    
            except OSError as oserror:
                print("Error when killing process #{}".format(process_id), oserror)
        
        try:
            os.kill(self.__listener_process.pid, signal.SIGINT)
        except OSError as oserror:
            print("Error when killing listener process #{}".format(
                self.__listener_process.pid), 
                oserror)

        print("All jobs are done and exited.")
        del self.__workers


if __name__ == "__main__":
    start_ip = ipaddress.IPv4Address(sys.argv[1])
    end_ip   = ipaddress.IPv4Address(sys.argv[2])

    workers  = sys.argv[3]

    manager = Manager(
        int(start_ip),
        int(end_ip),
        int(workers)
    )
    manager.run()
                

