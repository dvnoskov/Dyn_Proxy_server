import multiprocessing
import subprocess



def worker_stop(pid):
    pass

    #subprocess.Popen._closed_child_pipe_fds(pid)


def worker_start(file):
    process=subprocess.Popen(['python', file])
   # print(process.pid)
    work={}
    work[file]=process.pid
   # print(work)
    return work,process

if __name__ == "__main__":
    work = {}
    files = ['listen_DNS.py', 'listen_DynDNS.py','dog_server_DNS.py']
    z = 1
    while True:
        if len(files)>= z:
            for i in files:
                print(i)
                p = multiprocessing.Process(target = worker_start(i))
                p.start()
                z=z+1
        else :
            break


        print("working, input to stop = stop")
    while True:
        if input() == "stop":
            for i in files:
                worker_stop(work[i])
                print(work[i])
            break

