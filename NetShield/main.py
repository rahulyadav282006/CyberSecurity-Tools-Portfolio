# from packet_capture import start_sniffing

# def main():
#     print("NetShield Starting...\n")
#     start_sniffing()

# if __name__ == "__main__":
#     main()



from packet_capture import start_sniffing
from dashboard import show_dashboard
import threading
import time

def dashboard_loop():
    while True:
        show_dashboard()
        time.sleep(3)

def main():
    print("NetShield Starting...\n")

    t1 = threading.Thread(target=start_sniffing)
    t2 = threading.Thread(target=dashboard_loop)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

if __name__ == "__main__":
    main()