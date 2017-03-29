# Network-Security-Project
Capture RTP packets from a live stream, create a dummy RTP packet with garbage data, inject packet timely back into RTP stream to disrupt the service.

## Steps to execute program

### 1. Clear all previous controllers and clean the network:
```
bash networkClean
```

### 2. Start the network:
 ```
 bash networkStart
 ```
 
 ### 3. Start VLC player on host 1 (h1) and host 2 (h2). Host 3 (h3) is the attacker:
 ```
 vlc-wrapper &
 ```