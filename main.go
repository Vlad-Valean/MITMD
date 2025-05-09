package main

import (
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var lastAlert string = "Totul este OK."

func setupLogging() {
	logFile, err := os.OpenFile("mitm_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal("Eroare la deschiderea fisierului de log:", err)
	}
	log.SetOutput(logFile)
	log.Println("=== Pornire monitorizare MITM ===")
}

func sendEmailAlert(subject, body string) error {
	from := "youremail@example.com"
	password := "yourpassword"
	to := "alertrecipient@example.com"
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	msg := "Subject: " + subject + "\n\n" + body
	auth := smtp.PlainAuth("", from, password, smtpHost)

	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(msg))
}

func monitorARP() {
	iface := "eth0"
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Println("Eroare la deschiderea interfetei:", err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			srcIP := arp.SourceProtAddress
			srcMAC := arp.SourceHwAddress

			alert := fmt.Sprintf("[ARP] %v la MAC %v", srcIP, srcMAC)
			log.Println(alert)

			if srcIP[3] == 1 {
				message := fmt.Sprintf("Avertisment posibil ARP Spoofing: %v => %v", srcIP, srcMAC)
				log.Println(message)
				setAlert(message)
				_ = sendEmailAlert("MITM Alerta ARP", message)
			}
		}
	}
}

func setAlert(msg string) {
	lastAlert = msg
	log.Println("ALERTA:", msg)
}

func startWebUI() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<h1>Monitor MITM</h1><p>%s</p>", lastAlert)
	})
	go func() {
		log.Println("Server web pe http://localhost:8888")
		log.Fatal(http.ListenAndServe(":8888", nil))
	}()
}

func startAutoScanner(interval time.Duration, scanFunc func()) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			log.Println("Scanare periodica...")
			scanFunc()
		}
	}()
}

func main() {
	setupLogging()
	startWebUI()

	startAutoScanner(30*time.Second, func() {
		go monitorARP()
	})

	select {}
}
