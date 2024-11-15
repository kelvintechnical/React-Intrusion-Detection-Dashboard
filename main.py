from flask import Flask, request
from scapy.all import sniff
app = Flask(__name__)

@app.route('/')
def home():
    return "Welcome to the intrustion detection dashboard!"



# the app if the file is executed directly


@app.route("/detect", methods=["POST"])
def detect_intrusion():

    try:
        data = request.json
        text = data["text"]
    except KeyError:
        text = ""

    suspicious_keywords = [
        "hack", "malware", "attack", "phishing", "breach", "exploit", 
        "ransomware", "spyware", "virus", "worm", "botnet", "keylogger", 
        "trojan", "ddos", "sql injection", "xss", "zero-day", "rootkit"
    ]

    for k in suspicious_keywords:
        if k in text.lower():
            return f"Suspicious activity detected {k} found!", 200
        
    return "No suspicious activity detected.", 200

@app.route("/start-capture", methods=["GET"])
def capture_packets():
    captured_info = []


    def packet_callback(packet):
        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst
            captured_info.append(f'Captured packet: {ip_src} -> {ip_dst}')
        
    sniff(count=10, prn=packet_callback, store=0)

    return "\n".join(captured_info)
if __name__=="__main__":
    app.run(debug=True) #start server in debug mode
